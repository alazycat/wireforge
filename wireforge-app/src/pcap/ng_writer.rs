//! pcapng file writer.

use std::io::Write;
use std::time::Duration;

use super::types::LinkType;

pub struct PcapNgWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapNgWriter<W> {
    pub fn new(mut writer: W, link_type: LinkType) -> Result<Self, std::io::Error> {
        // Section Header Block: byte-order magic, version 1.0, unknown length.
        let mut shb_body = Vec::with_capacity(16);
        shb_body.extend_from_slice(&0x1A2B3C4Du32.to_be_bytes());
        shb_body.extend_from_slice(&1u16.to_be_bytes()); // major version
        shb_body.extend_from_slice(&0u16.to_be_bytes()); // minor version
        shb_body.extend_from_slice(&u64::MAX.to_be_bytes()); // section length
        write_block(&mut writer, 0x0A0D0D0A, &shb_body)?;

        // Interface Description Block.
        let lt: u16 = match link_type {
            LinkType::Ethernet => 1,
            LinkType::Raw => 101,
            LinkType::LinuxSll => 113,
            LinkType::LinuxSll2 => 276,
            LinkType::Unknown(v) => v as u16,
        };
        let mut idb_body = Vec::with_capacity(8);
        idb_body.extend_from_slice(&lt.to_be_bytes()); // link type
        idb_body.extend_from_slice(&0u16.to_be_bytes()); // reserved
        idb_body.extend_from_slice(&65535u32.to_be_bytes()); // snap length
        write_block(&mut writer, 1, &idb_body)?;

        Ok(Self { writer })
    }

    pub fn write_epb(&mut self, ts: Duration, packet: &[u8]) -> Result<(), std::io::Error> {
        let micros = ts.as_micros().min(u64::MAX as u128) as u64;
        let padded_len = (packet.len() + 3) & !3;
        let mut body = Vec::with_capacity(20 + padded_len);
        body.extend_from_slice(&0u32.to_be_bytes()); // interface_id
        body.extend_from_slice(&((micros >> 32) as u32).to_be_bytes()); // ts_high
        body.extend_from_slice(&(micros as u32).to_be_bytes()); // ts_low
        body.extend_from_slice(&(packet.len() as u32).to_be_bytes()); // captured_len
        body.extend_from_slice(&(packet.len() as u32).to_be_bytes()); // original_len
        body.extend_from_slice(packet);
        body.resize(20 + padded_len, 0);

        write_block(&mut self.writer, 6, &body)?;
        self.writer.flush()
    }
}

/// Write a block with its total-length prefix and suffix.
fn write_block<W: Write>(
    writer: &mut W,
    block_type: u32,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let total_len = (12 + body.len()) as u32;
    writer.write_all(&block_type.to_be_bytes())?;
    writer.write_all(&total_len.to_be_bytes())?;
    writer.write_all(body)?;
    writer.write_all(&total_len.to_be_bytes())
}
