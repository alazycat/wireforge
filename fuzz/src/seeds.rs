//! Seed corpus — hand-crafted, mostly-valid protocol packets. The
//! mutation engine uses these as starting points so deep parse paths
//! (options, extension-header chains, DNS compression) are reached
//! immediately instead of by chance.

/// Parse a hex string with arbitrary whitespace into bytes.
fn unhex(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let hi = hex_val(bytes[i]);
            // Consume optional separator, then the low nibble.
            i += 1;
            while i < bytes.len() && !bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let lo = if i < bytes.len() {
                hex_val(bytes[i])
            } else {
                0
            };
            out.push(hi << 4 | lo);
        }
        i += 1;
    }
    out
}

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// All seed inputs. IPv4/TCP/UDP/DNS seeds use valid checksums where the
/// seed would otherwise be rejected before reaching deep fields.
pub fn all() -> Vec<Vec<u8>> {
    vec![
        // IPv4 + options (NOP, NOP, Router Alert), 16-byte UDP-ish payload.
        unhex(
            "46 00 00 28 ab cd 00 00 40 11 f7 2b c0 a8 01 01 c0 a8 01 02
             94 04 00 00
             30 39 30 3a 00 14 00 00 00 00 00 00 00 00 00 00",
        ),
        // IPv6 + Hop-by-Hop extension header + ICMPv6 echo request.
        unhex(
            "60 00 00 00 00 20 00 40
             20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
             20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 02
             3a 00 00 00 00 00 00 00
             80 00 00 00 00 01 00 01",
        ),
        // TCP with MSS / window-scale / SACK-permitted options.
        unhex(
            "00 50 00 50 00 00 00 01 00 00 00 02 50 02 ff ff aa bb 00 00
             02 04 05 b4 01 03 03 07 01 01 04 02",
        ),
        // UDP DNS-shaped payload.
        unhex(
            "00 35 00 35 00 0c 00 00 74 65 73 74",
        ),
        // Ethernet + one 802.1Q VLAN tag + minimal IPv4.
        unhex(
            "ff ff ff ff ff ff 00 11 22 33 44 55 81 00 00 64 08 00
             45 00 00 14 ab cd 00 00 40 01 00 00 c0 a8 01 01 c0 a8 01 02",
        ),
        // ARP request.
        unhex(
            "00 01 08 00 06 04 00 01
             00 11 22 33 44 55 c0 a8 01 01
             00 00 00 00 00 00 c0 a8 01 02",
        ),
        // GRE with checksum + key + sequence present.
        unhex(
            "30 00 08 00 be ef 00 01 de ad be ef 68 65 6c 6c 6f",
        ),
        // VXLAN with VNI 0x123456 + inner Ethernet frame.
        unhex(
            "08 00 00 00 12 34 56 00
             ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00 00 14
             00 01 00 00 40 11 00 00 c0 a8 01 01 c0 a8 01 02",
        ),
        // ICMPv4 echo request.
        unhex("08 00 f7 ff 00 01 00 01 70 69 6e 67"),
        // IGMPv3 membership report with one group record.
        unhex(
            "22 00 9c c4 00 00 00 01 01 00 00 02 e0 00 00 01",
        ),
        // DNS query (www.example.com A) + answer with compression pointer.
        unhex(
            "12 34 01 00 00 01 00 01 00 00 00 00
             03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01
             c0 0c 00 01 00 01 00 00 00 3c 00 04 7f 00 00 01",
        ),
        // HTTP request for the TCP application dispatcher.
        unhex(
            "00 50 00 50
             47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74
             3a 20 65 78 61 6d 70 6c 65 2e 63 6f 6d 0d 0a 0d 0a",
        ),
        // mDNS/LLMNR-shaped UDP DNS with TXT answer.
        unhex(
            "00 00 00 00 00 01 00 01 00 00 00 00
             09 5f 73 65 72 76 69 63 65 73 04 5f 64 6e 73 04 5f 75 64 70
             05 6c 6f 63 61 6c 00 00 0c 00 01
             c0 0c 00 0c 00 01 00 00 00 78 00 02 c0 0c",
        ),
        // SLL (Linux cooked capture).
        unhex(
            "00 00 00 01 00 06 00 11 22 33 44 55 00 00 08 00
             45 00 00 14 00 01 00 00 40 11 00 00 c0 a8 01 01 c0 a8 01 02",
        ),
        // SLL2.
        unhex(
            "01 00 00 00 00 01 00 00 00 02 00 00 00 00 00 00
             00 00 00 00 08 00 00 06 00 11 22 33 44 55 00 00
             45 00 00 14 00 01 00 00 40 06 00 00 c0 a8 01 01 c0 a8 01 02",
        ),
        // Ethernet PAUSE frame.
        unhex("88 08 00 01 00 02 00 03 00 04 00 05 00 06"),
        // Ethernet PFC frame.
        unhex(
            "88 08 01 01 01 01 02 02 03 03 04 04 05 05 06 06 07 07 08 08",
        ),
        // USBPcap pseudo-header.
        unhex(
            "00 00 00 00 00 00 00 00 01 00 00 00 02 00 01 00
             03 00 00 00 00 00 00 00 00 00 00",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_parse_to_expected_lengths() {
        assert_eq!(all().len(), 18);
        for seed in all() {
            assert!(!seed.is_empty());
        }
    }

    #[test]
    fn unhex_strips_whitespace() {
        assert_eq!(unhex("01 02 0a ff"), vec![0x01, 0x02, 0x0a, 0xff]);
        assert_eq!(unhex("0102 0a"), vec![0x01, 0x02, 0x0a]);
        assert_eq!(unhex("0"), vec![0x00]);
    }
}
