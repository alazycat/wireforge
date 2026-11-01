//! Declarative macro for custom fixed-header protocols.
//!
//! [`define_protocol!`](crate::define_protocol) is a lightweight,
//! `macro_rules!`-based equivalent of libpnet's `pnet_macros` derive. It covers
//! the most common custom-protocol shapes: fixed-size headers with unsigned
//! integer fields (big-endian), fixed-length byte-string fields, and a trailing
//! payload. From one declaration it generates:
//!
//! - a zero-copy parser struct (`new` / field getters / `payload` / `as_bytes`)
//! - a chained builder struct (field setters + `payload`, `build() -> Vec<u8>`)
//! - `impl Packet` integration with the common trait family
//!
//! Unlike `pnet_macros` it does not generate mutable in-place views, computed
//! fields, checksums, or variable-length headers — those remain hand-written.
//! See the gap analysis in the repository docs for the full comparison.

// Re-exports used by the generated code so it works in both `no_std + alloc`
// and std downstream crates (`alloc` is not in their extern prelude).
#[doc(hidden)]
pub use alloc::vec as protocol_vec;
#[doc(hidden)]
pub use alloc::vec::Vec as ProtocolVec;

/// Declare a custom fixed-header protocol.
///
/// # Syntax
///
/// ```text
/// define_protocol! {
///     $(#[$meta:meta])*
///     $vis packet $PacketName / $BuilderName, header_len $HEADER_LEN;
///     u8        $field @ $offset;
///     u16       $field @ $offset;
///     u32       $field @ $offset;
///     bytes[$N] $field @ $offset;
///     payload;
/// }
/// ```
///
/// - `header_len` is the fixed header size in bytes. All field offsets must
///   fall inside it (the parser only validates the total length against it).
/// - `u8` / `u16` / `u32` fields are read and written big-endian.
/// - `bytes[$N]` is a fixed-length byte-string field (`[u8; $N]` in the
///   builder).
/// - The builder always carries a trailing `payload` (settable via
///   `.payload(..)`), and the parser's `payload()` returns everything after
///   `header_len`. `payload;` in the declaration is optional documentation.
///
/// # Example
///
/// ```
/// use wireforge_core::define_protocol;
/// use wireforge_core::packet::Packet;
/// use wireforge_core::util::PacketBuilder;
///
/// define_protocol! {
///     /// A toy telemetry protocol: version, flags, opcode, sequence.
///     pub packet TelemetryPacket / TelemetryPacketBuilder, header_len 8;
///     u8 version @ 0;
///     u8 flags @ 1;
///     u16 opcode @ 2;
///     u32 sequence @ 4;
///     payload;
/// }
///
/// let bytes = TelemetryPacketBuilder::default()
///     .version(2)
///     .flags(0x80)
///     .opcode(0x002A)
///     .sequence(7)
///     .payload(b"hello")
///     .build();
///
/// let pkt = TelemetryPacket::new(&bytes).unwrap();
/// assert_eq!(pkt.version(), 2);
/// assert_eq!(pkt.flags(), 0x80);
/// assert_eq!(pkt.opcode(), 0x002A);
/// assert_eq!(pkt.sequence(), 7);
/// assert_eq!(pkt.payload(), b"hello");
///
/// // Integrates with the common Packet trait family.
/// fn payload_len<T: Packet>(p: &T) -> usize {
///     p.payload().len()
/// }
/// assert_eq!(payload_len(&pkt), 5);
/// ```
#[macro_export]
macro_rules! define_protocol {
    // ---- entry point ----
    ($(#[$meta:meta])* $vis:vis packet $name:ident / $bname:ident, header_len $hlen:expr; $($fields:tt)*) => {
        $crate::define_protocol! {
            @munch $(#[$meta])* $vis $name $bname $hlen ;
            [] [] [] []
            $($fields)*
        }
    };

    // ---- terminal: emit the generated code (single hygiene context) ----
    (@munch $(#[$meta:meta])* $vis:vis $name:ident $bname:ident $hlen:expr ;
        [$($u8f:ident @ $u8o:expr)*]
        [$($u16f:ident @ $u16o:expr)*]
        [$($u32f:ident @ $u32o:expr)*]
        [$($bf:ident @ $boff:expr , $bn:expr)*]) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        $vis struct $name<'a> {
            buf: &'a [u8],
        }

        impl<'a> $name<'a> {
            $crate::parser_new!($hlen);

            /// Raw bytes backing this packet.
            #[inline]
            pub fn as_bytes(&self) -> &'a [u8] {
                self.buf
            }

            /// Payload bytes after the fixed header.
            #[inline]
            pub fn payload(&self) -> &'a [u8] {
                &self.buf[($hlen).min(self.buf.len())..]
            }

            $(
                #[doc = concat!("`", stringify!($u8f), "` field (u8, offset ", stringify!($u8o), ").")]
                #[inline]
                pub fn $u8f(&self) -> u8 {
                    self.buf[$u8o]
                }
            )*

            $(
                #[doc = concat!("`", stringify!($u16f), "` field (big-endian u16, offset ", stringify!($u16o), ").")]
                #[inline]
                pub fn $u16f(&self) -> u16 {
                    $crate::util::read_u16be(&self.buf[$u16o..$u16o + 2])
                }
            )*

            $(
                #[doc = concat!("`", stringify!($u32f), "` field (big-endian u32, offset ", stringify!($u32o), ").")]
                #[inline]
                pub fn $u32f(&self) -> u32 {
                    $crate::util::read_u32be(&self.buf[$u32o..$u32o + 4])
                }
            )*

            $(
                #[doc = concat!("`", stringify!($bf), "` field (", stringify!($bn), "-byte string, offset ", stringify!($boff), ").")]
                #[inline]
                pub fn $bf(&self) -> &'a [u8] {
                    &self.buf[$boff..$boff + $bn]
                }
            )*
        }

        impl<'a> $crate::Packet for $name<'a> {
            fn packet(&self) -> &[u8] {
                self.buf
            }

            fn payload(&self) -> &[u8] {
                &self.buf[($hlen).min(self.buf.len())..]
            }
        }

        /// Builder generated by [`define_protocol`](crate::define_protocol).
        #[derive(Debug, Clone)]
        $vis struct $bname {
            $(
                #[doc = concat!("`", stringify!($u8f), "` field value.")]
                $u8f: u8,
            )*
            $(
                #[doc = concat!("`", stringify!($u16f), "` field value.")]
                $u16f: u16,
            )*
            $(
                #[doc = concat!("`", stringify!($u32f), "` field value.")]
                $u32f: u32,
            )*
            $(
                #[doc = concat!("`", stringify!($bf), "` field value.")]
                $bf: [u8; $bn],
            )*
            /// Trailing payload bytes appended after the header.
            payload: $crate::define_protocol::ProtocolVec<u8>,
        }

        impl Default for $bname {
            fn default() -> Self {
                Self {
                    $( $u8f: 0u8, )*
                    $( $u16f: 0u16, )*
                    $( $u32f: 0u32, )*
                    $( $bf: [0u8; $bn], )*
                    payload: $crate::define_protocol::ProtocolVec::new(),
                }
            }
        }

        impl $bname {
            $(
                #[doc = concat!("Set the `", stringify!($u8f), "` field.")]
                pub fn $u8f(mut self, value: u8) -> Self {
                    self.$u8f = value;
                    self
                }
            )*

            $(
                #[doc = concat!("Set the `", stringify!($u16f), "` field.")]
                pub fn $u16f(mut self, value: u16) -> Self {
                    self.$u16f = value;
                    self
                }
            )*

            $(
                #[doc = concat!("Set the `", stringify!($u32f), "` field.")]
                pub fn $u32f(mut self, value: u32) -> Self {
                    self.$u32f = value;
                    self
                }
            )*

            $(
                #[doc = concat!("Set the `", stringify!($bf), "` field.")]
                pub fn $bf(mut self, value: [u8; $bn]) -> Self {
                    self.$bf = value;
                    self
                }
            )*

            /// Set the payload bytes appended after the header.
            pub fn payload(mut self, data: &[u8]) -> Self {
                self.payload = data.to_vec();
                self
            }
        }

        impl $crate::util::PacketBuilder for $bname {
            type Output = $crate::define_protocol::ProtocolVec<u8>;

            fn build(self) -> Self::Output {
                let mut buf = $crate::define_protocol::protocol_vec![0u8; $hlen];
                $( buf[$u8o] = self.$u8f; )*
                $( $crate::util::write_u16be(&mut buf[$u16o..$u16o + 2], self.$u16f); )*
                $( $crate::util::write_u32be(&mut buf[$u32o..$u32o + 4], self.$u32f); )*
                $( buf[$boff..$boff + $bn].copy_from_slice(&self.$bf); )*
                buf.extend_from_slice(&self.payload);
                buf
            }
        }
    };

    // ---- u8 field ----
    (@munch $(#[$meta:meta])* $vis:vis $name:ident $bname:ident $hlen:expr ;
        [$($u8:tt)*] [$($u16:tt)*] [$($u32:tt)*] [$($b:tt)*]
        u8 $f:ident @ $off:expr; $($rest:tt)*) => {
        $crate::define_protocol! {
            @munch $(#[$meta])* $vis $name $bname $hlen ;
            [$($u8)* $f @ $off] [$($u16)*] [$($u32)*] [$($b)*]
            $($rest)*
        }
    };

    // ---- u16 field (big-endian) ----
    (@munch $(#[$meta:meta])* $vis:vis $name:ident $bname:ident $hlen:expr ;
        [$($u8:tt)*] [$($u16:tt)*] [$($u32:tt)*] [$($b:tt)*]
        u16 $f:ident @ $off:expr; $($rest:tt)*) => {
        $crate::define_protocol! {
            @munch $(#[$meta])* $vis $name $bname $hlen ;
            [$($u8)*] [$($u16)* $f @ $off] [$($u32)*] [$($b)*]
            $($rest)*
        }
    };

    // ---- u32 field (big-endian) ----
    (@munch $(#[$meta:meta])* $vis:vis $name:ident $bname:ident $hlen:expr ;
        [$($u8:tt)*] [$($u16:tt)*] [$($u32:tt)*] [$($b:tt)*]
        u32 $f:ident @ $off:expr; $($rest:tt)*) => {
        $crate::define_protocol! {
            @munch $(#[$meta])* $vis $name $bname $hlen ;
            [$($u8)*] [$($u16)*] [$($u32)* $f @ $off] [$($b)*]
            $($rest)*
        }
    };

    // ---- fixed-length byte-string field ----
    (@munch $(#[$meta:meta])* $vis:vis $name:ident $bname:ident $hlen:expr ;
        [$($u8:tt)*] [$($u16:tt)*] [$($u32:tt)*] [$($b:tt)*]
        bytes[$n:expr] $f:ident @ $off:expr; $($rest:tt)*) => {
        $crate::define_protocol! {
            @munch $(#[$meta])* $vis $name $bname $hlen ;
            [$($u8)*] [$($u16)*] [$($u32)*] [$($b)* $f @ $off , $n]
            $($rest)*
        }
    };

    // ---- optional trailing payload marker ----
    (@munch $(#[$meta:meta])* $vis:vis $name:ident $bname:ident $hlen:expr ;
        [$($u8:tt)*] [$($u16:tt)*] [$($u32:tt)*] [$($b:tt)*]
        payload; $($rest:tt)*) => {
        $crate::define_protocol! {
            @munch $(#[$meta])* $vis $name $bname $hlen ;
            [$($u8)*] [$($u16)*] [$($u32)*] [$($b)*]
            $($rest)*
        }
    };
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::packet::{Packet, PacketSize};
    use crate::util::PacketBuilder;

    crate::define_protocol! {
        /// A toy telemetry protocol used by the macro tests.
        pub packet TelemetryPacket / TelemetryPacketBuilder, header_len 8;
        u8 version @ 0;
        u8 flags @ 1;
        u16 opcode @ 2;
        u32 sequence @ 4;
        payload;
    }

    crate::define_protocol! {
        /// A protocol with a fixed byte-string field.
        pub packet TaggedPacket / TaggedPacketBuilder, header_len 10;
        u16 tag @ 0;
        bytes[6] src_mac @ 2;
        u16 weight @ 8;
        payload;
    }

    #[test]
    fn parse_known_sample() {
        let bytes: Vec<u8> = vec![
            2, 0x80, 0x00, 0x2A, // version, flags, opcode
            0x00, 0x00, 0x00, 0x07, // sequence
            b'h', b'i', // payload
        ];
        let pkt = TelemetryPacket::new(&bytes).expect("long enough");
        assert_eq!(pkt.version(), 2);
        assert_eq!(pkt.flags(), 0x80);
        assert_eq!(pkt.opcode(), 0x002A);
        assert_eq!(pkt.sequence(), 7);
        assert_eq!(pkt.payload(), b"hi");
        assert_eq!(pkt.as_bytes().len(), 10);
    }

    #[test]
    fn too_short_is_none() {
        let bytes: Vec<u8> = vec![1, 2, 3];
        assert!(TelemetryPacket::new(&bytes).is_none());
    }

    #[test]
    fn builder_roundtrip() {
        let bytes = TelemetryPacketBuilder::default()
            .version(9)
            .flags(0x01)
            .opcode(0xBEEF)
            .sequence(0x0102_0304)
            .payload(b"\x01\x02\x03")
            .build();
        let pkt = TelemetryPacket::new(&bytes).expect("long enough");
        assert_eq!(pkt.version(), 9);
        assert_eq!(pkt.flags(), 0x01);
        assert_eq!(pkt.opcode(), 0xBEEF);
        assert_eq!(pkt.sequence(), 0x0102_0304);
        assert_eq!(pkt.payload(), b"\x01\x02\x03");
    }

    #[test]
    fn bytes_field_roundtrip() {
        let bytes = TaggedPacketBuilder::default()
            .tag(0x0800)
            .src_mac([1, 2, 3, 4, 5, 6])
            .weight(42)
            .payload(b"body")
            .build();
        let pkt = TaggedPacket::new(&bytes).expect("long enough");
        assert_eq!(pkt.tag(), 0x0800);
        assert_eq!(pkt.src_mac(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(pkt.weight(), 42);
        assert_eq!(pkt.payload(), b"body");
        assert_eq!(pkt.as_bytes().len(), 14);
    }

    #[test]
    fn defaults_are_zero() {
        let bytes = TelemetryPacketBuilder::default().build();
        assert_eq!(bytes.len(), 8);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn integrates_with_packet_trait() {
        let bytes = TelemetryPacketBuilder::default()
            .version(1)
            .payload(b"xyz")
            .build();
        let pkt = TelemetryPacket::new(&bytes).expect("long enough");
        fn payload_len<T: Packet>(p: &T) -> usize {
            p.payload().len()
        }
        assert_eq!(payload_len(&pkt), 3);
        assert_eq!(pkt.packet_size(), 11);
    }
}
