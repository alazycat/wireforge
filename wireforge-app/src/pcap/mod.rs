//! pcap and pcapng file reader/writer.

mod types;
mod reader;
mod writer;
mod ng_reader;
mod ng_writer;

pub use types::{Endianness, LinkType, PcapHeader, PcapRecordHeader, PcapNgBlock};
pub use reader::PcapReader;
pub use writer::PcapWriter;
pub use ng_reader::PcapNgReader;
pub use ng_writer::PcapNgWriter;

/// Common interface for reading packet captures (pcap or pcapng).
///
/// Two adapters implement this trait: [`PcapReader`] and [`PcapNgReader`].
/// Both yield `(timestamp, raw_packet_data)` tuples regardless of the
/// underlying file format.
pub trait PacketCaptureReader {
    type Error;

    /// The link-layer type of the captured packets, if known.
    fn link_type(&self) -> Option<LinkType>;

    /// Read the next captured packet. Returns `None` at end-of-file.
    #[allow(clippy::type_complexity)]
    fn next_packet(&mut self) -> Option<Result<(std::time::Duration, Vec<u8>), Self::Error>>;
}
