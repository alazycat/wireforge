//! pcapng file writer.

use std::io::Write;
use std::time::Duration;

use super::types::LinkType;

pub struct PcapNgWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapNgWriter<W> {
    pub fn new(mut writer: W, link_type: LinkType) -> Result<Self, std::io::Error> {
        // Write SHB
        let shb_body = [0u8; 16]; // byte_order_magic(4) + major(2) + minor(2) + section_len(8)
        let shb_len = 28u32; // 4(type) + 4(len) + 16(body) + 4(len)
        writer.write_all(&0x0A0D0D0Au32.to_be_bytes())?;
        writer.write_all(&shb_len.to_be_bytes())?;
        writer.write_all(&shb_body)?;
        writer.write_all(&shb_len.to_be_bytes())?;

        // Write IDB
        let lt: u16 = match link_type { LinkType::Ethernet => 1, LinkType::Raw => 101, LinkType::Unknown(v) => v as u16 };
        let mut idb_body = vec![0u8; 16];
        idb_body[8..10].copy_from_slice(&lt.to_le_bytes()); // link_type at offset 8
        let idb_len = 32u32; // 4(type) + 4(len) + 16(body) + 4(len)
        writer.write_all(&1u32.to_be_bytes())?;
        writer.write_all(&idb_len.to_be_bytes())?;
        writer.write_all(&idb_body)?;
        writer.write_all(&idb_len.to_be_bytes())?;

        Ok(Self { writer })
    }

    pub fn write_epb(&mut self, ts: Duration, packet: &[u8]) -> Result<(), std::io::Error> {
        let padded_len = (packet.len() + 3) & !3;
        let epb_body_len = 20 + padded_len;
        let epb_total_len = 12 + epb_body_len; // 4(type) + 4(len) + body + 4(len)

        self.writer.write_all(&6u32.to_be_bytes())?;
        self.writer.write_all(&(epb_total_len as u32).to_be_bytes())?;
        self.writer.write_all(&0u32.to_be_bytes())?; // interface_id
        self.writer.write_all(&(ts.as_secs() as u32).to_be_bytes())?; // ts_high
        self.writer.write_all(&ts.subsec_nanos().to_be_bytes())?; // ts_low
        self.writer.write_all(&(packet.len() as u32).to_be_bytes())?; // captured_len
        self.writer.write_all(&(packet.len() as u32).to_be_bytes())?; // original_len
        self.writer.write_all(packet)?;
        // Padding
        if padded_len > packet.len() {
            self.writer.write_all(&vec![0u8; padded_len - packet.len()])?;
        }
        self.writer.write_all(&(epb_total_len as u32).to_be_bytes())?;
        self.writer.flush()
    }
}
