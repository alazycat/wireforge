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

/// pcap link-layer header type (the `DLT_*` value from the pcap file header).
///
/// Canonical definition lives in `wireforge_core::link`; re-exported here
/// so pcap readers/writers and `wireforge-packet`'s `parse_link_layer`
/// share one type. Note: `Unknown(v)` values from older releases are now
/// `LinkType::Other(v as i32)`.
pub use wireforge_core::link::LinkType;

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
