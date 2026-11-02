//! pcap link-layer header type (the `DLT_*` value from the pcap file header).
//!
//! This is the single canonical definition shared by `wireforge-packet`
//! (link-layer dispatch) and `wireforge-app` (pcap/pcapng file I/O).
//!
//! Note on conventions: `from_dlt`/`dlt` use the libpcap *DLT_* numbering,
//! where `DLT_RAW` is 12 on most platforms (101 on OpenBSD). Pcap *files*
//! store LINKTYPE values instead, where raw IP is always 101 — callers
//! writing pcap global headers should map [`LinkType::Raw`] to 101.

/// Maps the pcap global-header `network` field to the correct
/// link-layer parser. Values most relevant to WireForge are named;
/// everything else falls back to [`LinkType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkType {
    /// `DLT_EN10MB` (1) — Ethernet II frames.
    Ethernet,
    /// `DLT_RAW` (12; 101 on OpenBSD) — raw IP packets, version detected
    /// from the IP header nibble.
    Raw,
    /// `DLT_LINUX_SLL` (113) — Linux cooked capture v1 (`tcpdump -i any`).
    LinuxSll,
    /// `DLT_LINUX_SLL2` (276) — Linux cooked capture v2 (newer tcpdump).
    LinuxSll2,
    /// `LINKTYPE_USBPCAP` (249) — USBPcap USB traffic captures (Windows).
    UsbPcap,
    /// Any other DLT value, held verbatim.
    Other(i32),
}

impl LinkType {
    /// Map a raw pcap `DLT_*` value to a [`LinkType`].
    ///
    /// Both DLT numbering conventions for raw IP are accepted:
    /// 12 (`DLT_RAW` on most platforms) and 101 (OpenBSD `DLT_RAW` /
    /// file-format `LINKTYPE_RAW`).
    pub fn from_dlt(v: i32) -> Self {
        match v {
            1 => LinkType::Ethernet,
            12 | 101 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            249 => LinkType::UsbPcap,
            other => LinkType::Other(other),
        }
    }

    /// The canonical raw pcap `DLT_*` value for this link type.
    pub fn dlt(self) -> i32 {
        match self {
            LinkType::Ethernet => 1,
            LinkType::Raw => 12,
            LinkType::LinuxSll => 113,
            LinkType::LinuxSll2 => 276,
            LinkType::UsbPcap => 249,
            LinkType::Other(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlt_mapping() {
        assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
        assert_eq!(LinkType::from_dlt(12), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(101), LinkType::Raw);
        assert_eq!(LinkType::from_dlt(113), LinkType::LinuxSll);
        assert_eq!(LinkType::from_dlt(276), LinkType::LinuxSll2);
        assert_eq!(LinkType::from_dlt(249), LinkType::UsbPcap);
        assert_eq!(LinkType::from_dlt(999), LinkType::Other(999));
    }

    #[test]
    fn dlt_roundtrip() {
        assert_eq!(LinkType::Ethernet.dlt(), 1);
        assert_eq!(LinkType::Raw.dlt(), 12);
        assert_eq!(LinkType::LinuxSll.dlt(), 113);
        assert_eq!(LinkType::LinuxSll2.dlt(), 276);
        assert_eq!(LinkType::UsbPcap.dlt(), 249);
        assert_eq!(LinkType::Other(777).dlt(), 777);
    }
}
