//! pcap/pcapng type definitions.

/// pcap global file header (24 bytes).
#[repr(C)]
pub struct PcapHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

/// pcap per-packet record header (16 bytes).
#[repr(C)]
pub struct PcapRecordHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Big,
    Little,
}

impl Endianness {
    /// Decode a u16 from the first two bytes of `buf`.
    pub(crate) fn read_u16(self, buf: &[u8]) -> u16 {
        match self {
            Self::Big => u16::from_be_bytes([buf[0], buf[1]]),
            Self::Little => u16::from_le_bytes([buf[0], buf[1]]),
        }
    }

    /// Decode a u32 from the first four bytes of `buf`.
    pub(crate) fn read_u32(self, buf: &[u8]) -> u32 {
        match self {
            Self::Big => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            Self::Little => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Raw,
    /// Linux cooked capture v1 — emitted by `tcpdump -i any`.
    LinuxSll,
    /// Linux cooked capture v2 — emitted by newer tcpdump releases.
    LinuxSll2,
    Unknown(u32),
}

impl From<u32> for LinkType {
    fn from(v: u32) -> Self {
        match v {
            1 => LinkType::Ethernet,
            101 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            _ => LinkType::Unknown(v),
        }
    }
}

/// pcapng block types.
#[derive(Debug, Clone)]
pub enum PcapNgBlock {
    SectionHeader {
        byte_order: Endianness,
        version: u16,
    },
    InterfaceDescription {
        link_type: LinkType,
        snap_len: u32,
    },
    EnhancedPacket {
        timestamp: std::time::Duration,
        data: Vec<u8>,
    },
    Unknown {
        block_type: u32,
        data: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_type_from_dlt_values() {
        assert_eq!(LinkType::from(1), LinkType::Ethernet);
        assert_eq!(LinkType::from(101), LinkType::Raw);
        assert_eq!(LinkType::from(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from(276), LinkType::LinuxSll2);
        assert_eq!(LinkType::from(999), LinkType::Unknown(999));
    }
}
