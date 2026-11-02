# Migrating wireforge-packet — LinkType Consolidation and `parse_capture`

This guide covers the dispatch-layer changes introduced alongside
wireforge-packet 1.2.0: the `LinkType` definition moving down to
`wireforge-core`, the matching changes in `wireforge-app`'s pcap module,
and the new optional `parse_capture` bridge.

## What changed and why

Before 1.2.0 the repository had two independent, structurally identical
`LinkType` enums:

| Old location | Shape | Consumers |
|---|---|---|
| `wireforge_packet::LinkType` | `Other(i32)`, `from_dlt`/`dlt`, `#[non_exhaustive]` | link-layer dispatch only |
| `wireforge_app::pcap::LinkType` | `Unknown(u32)`, `From<u32>`, exhaustive | pcap/pcapng file I/O only |

The two enums had already drifted: the packet version accepted both
DLT_RAW encodings (12 and 101), while the app version only accepted 101 —
so pcap files written by Linux `tcpdump -w` (`network = 12`) were
misclassified as `Unknown(12)`. The definition now lives once, in
`wireforge_core::link`, and both crates re-export it.

## Quick Reference — what moved

| Before (≤ 1.1) | After (1.2) | Notes |
|---|---|---|
| `wireforge_packet::LinkType` (defined in packet) | `wireforge_packet::LinkType` (re-export of `wireforge_core::link::LinkType`) | Path unchanged; same type |
| `wireforge_app::pcap::LinkType` (own enum) | re-export of the same core type | Path unchanged; type unified |
| `LinkType::Unknown(u32)` (app) | `LinkType::Other(i32)` | **Breaking**: rename + payload type |
| `LinkType::from(u32)` (app) | `LinkType::from_dlt(i32)` | **Breaking**: inherent method |
| `wireforge_app` has no dependency on `wireforge-packet` (the orphan-crate problem) | optional dep behind the `dispatch` feature | Opt-in bridge |

---

## Breaking change 1: `Unknown(u32)` → `Other(i32)`

If you matched on the app-side variant:

### Before
```rust
use wireforge_app::pcap::LinkType;

match link_type {
    LinkType::Ethernet => { /* ... */ }
    LinkType::Unknown(v) => println!("unrecognized DLT {v}"),
    _ => { /* ... */ }
}
```

### After
```rust
use wireforge_app::pcap::LinkType;

match link_type {
    LinkType::Ethernet => { /* ... */ }
    LinkType::Other(v) => println!("unrecognized DLT {v}"),
    // `LinkType` is #[non_exhaustive] — a wildcard arm is now mandatory
    // when matching from outside the defining crate.
    _ => { /* ... */ }
}
```

Two adjustments in one: the variant is renamed (`Unknown` → `Other`),
its payload widens conceptually from `u32` to `i32` (libpcap `DLT_*`
values are signed), and — because the canonical enum is
`#[non_exhaustive]` — **exhaustive matches from any downstream crate now
require a wildcard arm**. If your old match had no `_` arm, the compiler
will point at every site.

## Breaking change 2: `From<u32>` → `from_dlt(i32)`

### Before
```rust
let lt = wireforge_app::pcap::LinkType::from(header.network); // u32
```

### After
```rust
let lt = wireforge_app::pcap::LinkType::from_dlt(header.network as i32);
```

The core type intentionally does not provide `From<u32>`: raw `DLT_*`
values are conventionally `i32`, and a silent `as` cast at the call site
makes the (lossless for all real DLT values) conversion visible.

## Behavior fix: DLT_RAW = 12 now maps to `Raw`

Both encodings of raw IP are accepted everywhere:

- `12` — `DLT_RAW` on most platforms (what `tcpdump -w` writes on Linux)
- `101` — `DLT_RAW` on OpenBSD / the pcap file-format `LINKTYPE_RAW`

Writers still emit **101** for `LinkType::Raw`, because pcap files store
`LINKTYPE_*` values — the DLT/LINKTYPE distinction is documented on
`wireforge_core::link`. Round-trips through `PcapWriter`/`PcapNgWriter`
are unchanged; only previously-misread `network = 12` files are fixed.

---

## New capability: `parse_capture` (feature `dispatch`)

wireforge-app can now walk a raw capture record through every layer —
link → network → transport → application — using wireforge-packet's
dispatch. Enable it in `Cargo.toml`:

```toml
[dependencies]
wireforge-app = { version = "1.2", features = ["dispatch"] }
```

### Before: manual bridging across two crates (≤ 1.1)

```rust
use wireforge_app::pcap::{PcapReader, LinkType as PcapLinkType};
use wireforge_packet::{parse_ethernet_frame, parse_ipv4_payload, Packet};
use wireforge_core::types::IpProtocol;

let reader = PcapReader::from_bytes(data)?;
// 1. Convert between the two incompatible LinkType enums by hand
let link = match reader.link_type() {
    PcapLinkType::Ethernet => wireforge_packet::LinkType::Ethernet,
    PcapLinkType::Raw => wireforge_packet::LinkType::Raw,
    // ... every variant spelled out
    PcapLinkType::Unknown(v) => wireforge_packet::LinkType::Other(v as i32),
};
for rec in reader {
    let (_, buf) = rec?;
    // 2. Walk the stack yourself, level by level
    let Some((_, l3)) = parse_ethernet_frame(&buf) else { continue };
    let Packet::Ipv4(ip) = l3 else { continue };
    if let Some(l4) = parse_ipv4_payload(&ip) {
        // 3. Extract ports and call the app dispatch manually
        if let Packet::Udp(udp) = &l4 {
            if let Some(app) = wireforge_app::app_packet::parse_udp_application(
                udp.payload(), udp.source_port(), udp.destination_port())
            {
                println!("{}", app.protocol_name());
            }
        }
    }
}
```

### After: one call

```rust
use wireforge_app::pcap::{parse_capture, PcapReader};

let reader = PcapReader::from_bytes(data)?;
let link = reader.link_type(); // pcap files: a plain LinkType, not an Option
for rec in reader {
    let (_, buf) = rec?;
    // A hopeless frame (shorter than its link header) yields None —
    // skip it rather than aborting the whole pass.
    let Some(parsed) = parse_capture(&buf, link) else { continue };
    // parsed.link / parsed.network / parsed.transport / parsed.app
    if let Some(app) = &parsed.app {
        println!("{}", app.protocol_name()); // e.g. "mDNS"
    }
}
```

> `PcapNgReader::link_type()` returns `Option<LinkType>` instead — it is
> `None` until the first Interface Description Block is seen — so unwrap
> (or default) once before the record loop, exactly as shown here.

`parse_capture` never allocates and never takes ownership of the buffer:
`ParsedCapture<'a>` borrows the record bytes, so the borrow ends with the
loop iteration. Layers that fail to parse stay `None`; only a frame too
short for its link header returns `None` overall. VXLAN (UDP 4789) is
dispatched as an ordinary UDP payload — inner-frame recursion is
intentionally out of scope for now.

The bridge respects the original layering: without the `dispatch`
feature, wireforge-app keeps no dependency on wireforge-packet and its
default build is unchanged.

---

## Bridging API design notes

This section documents *why* `parse_capture` looks the way it does, so
you can judge whether your own glue should follow the same rules.

### 1. A free function, not a struct or trait

The entry point is deliberately a plain function:

```rust
pub fn parse_capture(buf: &[u8], link: LinkType) -> Option<ParsedCapture<'_>>
```

A session object (`CaptureParser::new(&buf).parse()`) would have to store
the `&[u8]` *and* hand out views that borrow it, which in Rust forces
either a self-referential struct (unsafe, unsound under moves) or
lifetimes threaded through every method (`fn parse<'s>(&'s mut self)`
— workable, but the returned `ParsedCapture` then pins the parser for
the whole loop iteration, and a `&mut self` borrow shared across fields
collides as soon as one method writes state). A free function borrows
`buf` exactly once and returns a value whose lifetime is that borrow;
the caller's record loop stays trivially borrow-checked.

### 2. `ParsedCapture<'a>` — every field borrows the record

```rust
pub struct ParsedCapture<'a> {
    pub link: LinkPacket<'a>,
    pub network: Option<Packet<'a>>,
    pub transport: Option<Packet<'a>>,
    pub app: Option<AppPacket<'a>>,
}
```

- Zero allocation: `network`/`transport` are `Packet<'a>` enum views, so
  even the *clones* inside `parse_capture` are `Copy`-like enum-variant
  copies of references, not payload copies.
- The borrow ends with the loop iteration — drop-or-reuse the value
  before moving on to the next record. If you need to retain a field
  past the iteration, `.to_owned()` that field explicitly.
- `Debug + Clone` are derived; `Clone` is cheap for the same reason.

### 3. The walk algorithm

`parse_capture` walks the stack in three steps, mirroring the crate
layering:

1. **Link**: `wireforge_packet::parse_link_layer(link, buf)` — one call
   handles all five supported link types (`Ethernet`, `Raw`,
   `LinuxSll`, `LinuxSll2`, `UsbPcap`); `Raw` records are raw IP with
   the version detected from the header nibble. This is the
   only step that can fail the whole call.
2. **Network/transport**: repeatedly calls `Packet::inner()` while the
   current packet is `Ipv4`/`Ipv6` (the only recursing variants). Each
   TCP/UDP leaf captures `(payload, src_port, dst_port, is_tcp)` *into
   a local tuple* while the packet view is still alive here; ICMP /
   ICMPv6 / ARP and other leaves stop the walk.
3. **Application**: the captured tuple feeds
   `parse_tcp_application` / `parse_udp_application`, so the app
   dispatch borrows straight into the original record buffer rather
   than through the transport view.

Why the local tuple instead of keeping a `&Packet` reference: the
transport `Packet<'_>` borrows from `network`'s payload which itself
borrows from `buf`; threading that chained lifetime into the app layer
is possible but makes the signature harder to read for no behavioral
gain. The 4-tuple is the minimal state needed and keeps every borrow a
direct one into `buf`.

### 4. Failure semantics — `Option` per layer, `None` for the frame

Failure is *layered*, not fatal:

| Condition | Result |
|---|---|
| Frame shorter than its link header (or an unparseable link layer) | `parse_capture` returns `None` for the whole record |
| Link OK, but the payload is not IP (e.g. ARP) | `network`/`transport`/`app` are `None` |
| IP OK, transport missing or unrecognized | `transport`/`app` are `None` |
| TCP/UDP present but ports/payload match no known app protocol | `app` is `None` only |

This means you can treat a capture as "best effort, report what
parsed" — the alternative (a `Result` with a per-layer error enum) was
rejected because most malformed real-world records are simply truncated,
and callers overwhelmingly want `match` on presence rather than error
classification. If you need the *reason* a layer is absent, drop back to
the manual walk shown in the "Before" section above — the free-function
API is intentionally lossy about *why*.

### 5. Feature gating: `dispatch = ["dep:wireforge-packet"]`

```toml
# wireforge-app/Cargo.toml
[features]
dispatch = ["dep:wireforge-packet"]

[dependencies]
wireforge-packet = { version = "1.2.0", path = "../wireforge-packet", optional = true }
```

Consequences worth knowing:

- Without the feature, `parse_capture`, `ParsedCapture`, and the
  `wireforge-packet` dependency do not exist in the build graph — the
  default build compiles and links exactly as before 1.2.
- Enabling the feature adds wireforge-packet to wireforge-app's
  dependency edge but does **not** transitively enable any
  wireforge-packet features (there are none beyond its defaults).
- Version alignment: wireforge-app 1.2 declares `wireforge-packet`
  `1.2.0`; Cargo resolves both to the same `wireforge-core` re-export,
  which is what makes the `LinkType` unification type-safe (a single
  enum definition, not two structurally identical ones).

### 6. Deliberately out of scope

- **VXLAN / inner-frame recursion**: a UDP datagram on port 4789 is
  dispatched as an ordinary UDP payload (`app` will not contain an
  inner `ParsedCapture`). Recursion would force `ParsedCapture` to be
  recursive (`app: Option<Box<ParsedCapture<'a>>>`), complicating the
  borrow story for an uncommon case. Revisit only if a concrete need
  appears.
- **Frag-reassembly, tunnel stripping, reassembly across records**:
  same reasoning — `parse_capture` is per-record, stateless, and
  zero-copy; anything requiring state belongs in a session layer above
  it.

### 7. Extending the dispatch

There are two extension paths depending on who you are.

#### 7a. Adding a first-party protocol (inside wireforge-app)

The app dispatch lives in one file,
`wireforge-app/src/app_packet.rs`. Because `parse_capture` calls
`parse_tcp_application` / `parse_udp_application` unconditionally, a
new protocol added there flows into the bridge with **no changes to
`dispatch.rs`**. The checklist for a new protocol `Foo`:

1. **Parser type** — implement `FooPacket<'a>` with a zero-copy
   constructor, following the house convention: `pub fn new(buf: &'a [u8])
   -> Option<Self>` (or `parse`, as `TlsClientHello` and `Smb2Header`
   do). `new` must validate lengths up front and never panic on
   truncated input; all accessors return borrowed slices of `buf`.
2. **Variant** — add `Foo(FooPacket<'a>)` to `AppPacket<'a>`
   ([app_packet.rs L37-48](../wireforge-app/src/app_packet.rs#L37-L48)). The
   enum is `#[non_exhaustive]`, so this is a minor-version change for
   downstream matchers.
3. **`protocol_name()` arm** — one line in the match at
   [app_packet.rs L52-65](../wireforge-app/src/app_packet.rs#L52-L65).
4. **`From` impl** — one line via the `from_impl!` macro
   ([app_packet.rs L68-87](../wireforge-app/src/app_packet.rs#L68-L87)):
   `from_impl!(Foo, FooPacket<'a>);`
5. **Port + dispatch arm** — add the IANA port to `mod ports`
   ([app_packet.rs L19-32](../wireforge-app/src/app_packet.rs#L19-L32)), then a
   `port_matches` block in `parse_tcp_application` or
   `parse_udp_application` ([app_packet.rs L109-150](../wireforge-app/src/app_packet.rs#L109-L150)).
   Dispatch is direction-agnostic (`src == port || dst == port`), so
   both request and response records are recognized.
6. **Tests** — add a dispatch test in `app_packet.rs` (byte-level
   fixture → assert variant + `protocol_name`) and, if the protocol
   should be visible end-to-end through the bridge, an integration test
   in `dispatch.rs`'s test module using the `eth_frame` helper.

Rules the existing parsers follow and new ones must too:

- **Borrow, don't copy**: the parser stores `&'a [u8]` windows into the
  record buffer. Anything that needs to own bytes belongs in a session
  layer, not here (see §6).
- **Parse on construction**: `new`/`parse` returning `Option` is the
  whole error contract; there is no deferred-validation state.
- **Port-based, single shot**: one port (or port pair) maps to one
  parser. If a protocol needs payload sniffing rather than port
  matching, discuss it first — that changes the dispatch contract for
  every protocol, not just yours.

#### 7b. Extending from downstream (outside the crates)

You **cannot** add variants to `AppPacket` from another crate — that is
what `#[non_exhaustive]` guarantees, and it is intentional: the enum is
the closed set of protocols this workspace ships. The supported
pattern is *side-channel dispatch*: run `parse_capture` first, then try
your own parser against the transport payload when app dispatch
declined.

```rust
use wireforge_app::app_packet::AppPacket;
use wireforge_app::pcap::{parse_capture, LinkType};
use wireforge_packet::Packet;

// Your own zero-copy app-layer parser.
struct MyProto<'a> { payload: &'a [u8] }
impl<'a> MyProto<'a> {
    fn new(buf: &'a [u8]) -> Option<Self> {
        (buf.len() >= 4 && buf[0] == 0xF0).then(|| MyProto { payload: buf })
    }
}

enum MyApp<'a> {
    Known(AppPacket<'a>),
    MyProto(MyProto<'a>),
}

fn dispatch<'a>(buf: &'a [u8], link: LinkType) -> Option<MyApp<'a>> {
    let parsed = parse_capture(buf, link)?;
    match parsed.app {
        Some(app) => Some(MyApp::Known(app)),
        // App dispatch declined — retry the transport payload ourselves.
        None => match parsed.transport.as_ref() {
            Some(Packet::Udp(udp)) if udp.destination_port() == 9999 => {
                MyProto::new(udp.payload()).map(MyApp::MyProto)
            }
            _ => None,
        },
    }
}
```

Why this shape works:

- The `MyProto` borrow comes from `parsed.transport`'s payload, which
  borrows from `buf` — the same lifetime `'a` flows through, so
  `MyApp<'a>` is plain borrow-checked code, no `unsafe`, no
  self-reference.
- Matching `parsed.transport` with a wildcard keeps you future-proof:
  when this workspace adds new `Packet` variants, your
  `match` still compiles (this is exactly the `#[non_exhaustive]`
  discipline from Breaking change 1, applied one layer down).
- If you also want port-based symmetry like the built-in dispatch,
  check `udp.source_port() == 9999 || udp.destination_port() == 9999`
  instead of just the destination — that mirrors
  `port_matches` in `app_packet.rs`.

When a side-channel parser becomes broadly useful, prefer contributing
it upstream (path 7a) over maintaining a fork of the dispatch: upstream
placement keeps the single-enum `protocol_name()` contract intact and
lets `parse_capture` users get it for free.

---

## Checklist

- [ ] Replace `LinkType::Unknown(v)` matches with `LinkType::Other(v as i32)` and add a wildcard arm where needed
- [ ] Replace `LinkType::from(x)` (app) with `LinkType::from_dlt(x as i32)`
- [ ] Re-check any code that special-cased `network = 12` pcap files — it now reports `Raw` correctly
- [ ] Optional: add `features = ["dispatch"]` to wireforge-app and delete your hand-rolled reader-to-parser glue
- [ ] Bump to wireforge-core/packet/app 1.2 together — the re-exports require matching versions
