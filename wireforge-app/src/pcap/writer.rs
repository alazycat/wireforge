//! pcap file writer.

use std::io::Write;
use std::time::Duration;

use super::types::LinkType;

pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W, link_type: LinkType) -> Result<Self, std::io::Error> {
        // Pcap files store LINKTYPE values, where raw IP is always 101 —
        // regardless of the platform DLT_RAW (12 vs 101) convention.
        let net: u32 = match link_type {
            LinkType::Ethernet => 1,
            LinkType::Raw => 101,
            LinkType::LinuxSll => 113,
            LinkType::LinuxSll2 => 276,
            LinkType::UsbPcap => 249,
            // `LinkType` is `#[non_exhaustive]`; fall back to the canonical
            // DLT value (covers `Other(v)` and any future variants).
            other => other.dlt() as u32,
        };
        writer.write_all(&0xa1b2c3d4u32.to_be_bytes())?; // magic
        writer.write_all(&2u16.to_be_bytes())?; // version major
        writer.write_all(&4u16.to_be_bytes())?; // version minor
        writer.write_all(&[0u8; 4])?; // thiszone
        writer.write_all(&[0u8; 4])?; // sigfigs
        writer.write_all(&65535u32.to_be_bytes())?; // snaplen
        writer.write_all(&net.to_be_bytes())?; // network
        Ok(Self { writer })
    }

    pub fn write(&mut self, ts: Duration, packet: &[u8]) -> Result<(), std::io::Error> {
        self.writer
            .write_all(&(ts.as_secs() as u32).to_be_bytes())?;
        self.writer.write_all(&ts.subsec_micros().to_be_bytes())?;
        self.writer
            .write_all(&(packet.len() as u32).to_be_bytes())?;
        self.writer
            .write_all(&(packet.len() as u32).to_be_bytes())?;
        self.writer.write_all(packet)?;
        self.writer.flush()
    }
}
