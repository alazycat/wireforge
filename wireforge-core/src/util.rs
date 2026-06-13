//! Byte-order helpers, checksum computation, error types.

// ---------------------------------------------------------------------------
// Big-endian byte read/write helpers
// ---------------------------------------------------------------------------

/// Read a big-endian u16 from a 2-byte slice. Caller guarantees `buf.len() >= 2`.
#[inline]
pub fn read_u16be(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

/// Read a big-endian u32 from a 4-byte slice. Caller guarantees `buf.len() >= 4`.
#[inline]
pub fn read_u32be(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Write a big-endian u16 into a 2-byte slice. Caller guarantees `buf.len() >= 2`.
#[inline]
pub fn write_u16be(buf: &mut [u8], val: u16) {
    buf[..2].copy_from_slice(&val.to_be_bytes());
}

/// Write a big-endian u32 into a 4-byte slice. Caller guarantees `buf.len() >= 4`.
#[inline]
pub fn write_u32be(buf: &mut [u8], val: u32) {
    buf[..4].copy_from_slice(&val.to_be_bytes());
}

// ---------------------------------------------------------------------------
// RFC 1071 Internet Checksum
// ---------------------------------------------------------------------------

/// Compute the 16-bit ones' complement of the ones' complement sum of `data`.
///
/// The result is in network byte order and is the value that should be
/// written into a checksum field so that verifying the entire header
/// (including the checksum field) yields zero.
///
/// For odd-length data, a virtual zero byte is appended for the final
/// 16-bit word.
pub fn internet_checksum(mut data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    while data.len() >= 2 {
        sum += read_u16be(data) as u32;
        data = &data[2..];
    }
    if !data.is_empty() {
        // Odd byte: pad with zero
        sum += (data[0] as u32) << 8;
    }
    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute the TCP/UDP pseudo-header checksum.
///
/// `src` and `dst` are the raw IP address bytes (4 bytes for IPv4, 16 for
/// IPv6). `protocol` is the IP protocol number. `transport_data` is the
/// TCP or UDP header + payload.
pub fn pseudo_header_checksum(src: &[u8], dst: &[u8], protocol: u8, transport_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Source address
    sum = add_slice_to_sum(sum, src);
    // Destination address
    sum = add_slice_to_sum(sum, dst);
    // Protocol (padded to 16 bits)
    sum += protocol as u32;
    // Transport-layer length
    sum += transport_data.len() as u32;
    // Transport data
    sum = add_slice_to_sum(sum, transport_data);

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn add_slice_to_sum(mut sum: u32, mut data: &[u8]) -> u32 {
    while data.len() >= 2 {
        sum += read_u16be(data) as u32;
        data = &data[2..];
    }
    if !data.is_empty() {
        sum += (data[0] as u32) << 8;
    }
    sum
}

// ---------------------------------------------------------------------------
// Builder error type
// ---------------------------------------------------------------------------

/// Error returned by packet builders when construction fails.
#[derive(Debug, Clone)]
pub enum BuildError {
    /// Payload exceeds the maximum allowed by this protocol.
    PayloadTooLarge { max: usize, actual: usize },
    /// A field value is out of range.
    InvalidField { field: &'static str, reason: &'static str },
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge { max, actual } => {
                write!(f, "payload too large: max {max} bytes, got {actual}")
            }
            Self::InvalidField { field, reason } => {
                write!(f, "invalid field `{field}`: {reason}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u16be_works() {
        assert_eq!(read_u16be(&[0x08, 0x00]), 0x0800);
        assert_eq!(read_u16be(&[0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn read_u32be_works() {
        assert_eq!(read_u32be(&[0xC0, 0xA8, 0x01, 0x01]), 0xC0A80101);
    }

    #[test]
    fn write_u16be_works() {
        let mut buf = [0u8; 2];
        write_u16be(&mut buf, 0x0800);
        assert_eq!(buf, [0x08, 0x00]);
    }

    #[test]
    fn write_u32be_works() {
        let mut buf = [0u8; 4];
        write_u32be(&mut buf, 0xC0A80101);
        assert_eq!(buf, [0xC0, 0xA8, 0x01, 0x01]);
    }

    // RFC 1071 test vectors
    #[test]
    fn checksum_empty() {
        // Ones' complement of zero is 0xFFFF
        assert_eq!(internet_checksum(&[]), 0xFFFF);
    }

    #[test]
    fn checksum_single_byte() {
        assert_eq!(internet_checksum(&[0x01]), 0xFEFF);
    }

    #[test]
    fn checksum_known_ip_header() {
        // A minimal valid IP header (20 bytes, checksum field zeroed)
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xAC, 0x10, 0x0A, 0x63,
            0xAC, 0x10, 0x0A, 0x0C,
        ];
        let checksum = internet_checksum(&header);
        // Verify that header with checksum inserted passes verification
        let mut with_checksum = header;
        with_checksum[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(internet_checksum(&with_checksum), 0);
    }

    #[test]
    fn pseudo_header_checksum_basic() {
        // IPv4 pseudo-header + minimal TCP header
        let src = [192u8, 168, 1, 1];
        let dst = [192u8, 168, 1, 2];
        let tcp_header = [0x00u8, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00];
        let csum = pseudo_header_checksum(&src, &dst, 6, &tcp_header);
        // Should compute a valid non-zero value
        assert_ne!(csum, 0);
    }

    #[test]
    fn checksum_roundtrip() {
        let data: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let csum = internet_checksum(&data);
        // Original data + checksum should verify to 0
        let mut combined = [0u8; 10];
        combined[..8].copy_from_slice(&data);
        combined[8..10].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(internet_checksum(&combined), 0);
    }
}
