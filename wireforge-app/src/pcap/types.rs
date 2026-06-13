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
pub enum Endianness { Big, Little }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType { Ethernet, Raw, Unknown(u32) }

impl From<u32> for LinkType {
    fn from(v: u32) -> Self {
        match v { 1 => LinkType::Ethernet, 101 => LinkType::Raw, _ => LinkType::Unknown(v) }
    }
}

/// pcapng block types.
#[derive(Debug, Clone)]
pub enum PcapNgBlock {
    SectionHeader { byte_order: Endianness, version: u16 },
    InterfaceDescription { link_type: LinkType, snap_len: u32 },
    EnhancedPacket { timestamp: std::time::Duration, data: Vec<u8> },
    Unknown { block_type: u32, data: Vec<u8> },
}
