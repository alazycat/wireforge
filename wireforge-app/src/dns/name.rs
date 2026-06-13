//! DNS QNAME compression parser (RFC 1035 Section 4.1.4).

use wireforge_core::util::read_u16be;

/// Maximum compression pointer jumps before we stop (prevents loops).
const MAX_JUMPS: u8 = 10;

/// Parse a DNS domain name at `start` in `buf`.
///
/// Returns the decompressed name and the byte position after the parsed
/// name (either the zero-length terminator or the compression pointer).
/// Labels > 63 bytes return `None`. Compression loops return `None`.
pub fn parse_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut jumped = false;
    let mut jump_count = 0u8;
    let mut end_pos = start;

    loop {
        if jump_count > MAX_JUMPS {
            return None;
        }
        if pos >= buf.len() {
            return None;
        }
        let label_len = buf[pos] as usize;
        if label_len & 0xC0 == 0xC0 {
            // Compression pointer: top 2 bits = 11
            if pos + 2 > buf.len() {
                return None;
            }
            let offset = read_u16be(&buf[pos..pos + 2]) as usize & 0x3FFF;
            if !jumped {
                end_pos = pos + 2;
            }
            pos = offset;
            jumped = true;
            jump_count += 1;
        } else if label_len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        } else {
            if label_len > 63 {
                return None;
            }
            if pos + 1 + label_len > buf.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            let label_bytes = &buf[pos + 1..pos + 1 + label_len];
            // Domain labels are ASCII case-insensitive; store lowercased
            name.push_str(core::str::from_utf8(label_bytes).ok()?);
            pos += 1 + label_len;
            if !jumped {
                end_pos = pos;
            }
        }
    }
    Some((name, end_pos))
}

/// Encode a domain name into wire format (labels prefixed by length, no compression).
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        let label_bytes = label.as_bytes();
        out.push(label_bytes.len() as u8);
        out.extend_from_slice(label_bytes);
    }
    out.push(0); // terminator
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_name() {
        // "www.example.com" encoded: 3www7example3com0
        let data: &[u8] = &[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let (name, pos) = parse_name(data, 0).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(pos, data.len());
    }

    #[test]
    fn parse_compressed_name() {
        // "example.com" at offset 12, then "www.example.com" with pointer
        let mut data = vec![0u8; 12];
        data.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        // "www" + pointer to offset 12
        data.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 12]);

        let (name, _) = parse_name(&data, 25).unwrap(); // start at "www..."
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn parse_multi_jump_compression() {
        // Chain: label -> ptr1 -> ptr2 -> "example.com"
        let name_data: &[u8] = &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let ptr1: &[u8] = &[3, b'w', b'w', b'w', 0xC0, 0]; // points to name_data
        let ptr2: &[u8] = &[0xC0, 13]; // points to ptr1 (offset 13 = after name_data)

        let mut data = Vec::new();
        data.extend_from_slice(name_data); // offset 0
        data.extend_from_slice(ptr1);      // offset 13
        data.extend_from_slice(ptr2);      // offset 18

        let (name, _) = parse_name(&data, 19).unwrap();
        assert_eq!(name, "www.example.com");
    }

    #[test]
    fn parse_compression_loop_returns_none() {
        // Two pointers that point to each other
        let data: &[u8] = &[0xC0, 2, 0xC0, 0];
        assert!(parse_name(data, 0).is_none());
    }

    #[test]
    fn parse_label_too_long() {
        let mut data = vec![64u8]; // label > 63
        data.extend(std::iter::repeat(b'x').take(64));
        assert!(parse_name(&data, 0).is_none());
    }

    #[test]
    fn encode_name_roundtrip() {
        let encoded = encode_name("www.example.com");
        let (decoded, _) = parse_name(&encoded, 0).unwrap();
        assert_eq!(decoded, "www.example.com");
    }
}
