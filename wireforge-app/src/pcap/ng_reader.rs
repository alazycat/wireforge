//! pcapng file reader.

use std::io::Read;
use std::time::Duration;

use super::types::{Endianness, LinkType, PcapNgBlock};

pub struct PcapNgReader<R: Read> {
    reader: R,
    link_type: Option<LinkType>,
    byte_order: Endianness,
}

impl<R: Read> PcapNgReader<R> {
    pub fn new(mut reader: R) -> Result<Self, std::io::Error> {
        // Read first block to determine byte order
        let mut hdr = [0u8; 8];
        reader.read_exact(&mut hdr)?;
        let block_type = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let _block_len = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        // SHB has type 0x0A0D0D0A
        let byte_order = if block_type == 0x0A0D0D0A { Endianness::Big } else { Endianness::Little };
        Ok(Self { reader, link_type: None, byte_order })
    }

    pub fn link_type(&self) -> Option<LinkType> { self.link_type }
}

impl<R: Read> Iterator for PcapNgReader<R> {
    type Item = Result<PcapNgBlock, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut hdr = [0u8; 8];
        match self.reader.read_exact(&mut hdr) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        }
        let block_type = read_u32(&hdr[0..4], self.byte_order);
        let block_len = read_u32(&hdr[4..8], self.byte_order) as usize;
        if block_len < 12 { return Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "block too short"))); }
        let body_len = block_len - 12;
        let mut body = vec![0u8; body_len];
        if let Err(e) = self.reader.read_exact(&mut body) { return Some(Err(e)); }
        // Read trailing block length
        let mut tail = [0u8; 4];
        let _ = self.reader.read_exact(&mut tail);

        let block = match block_type {
            0x0A0D0D0A => PcapNgBlock::SectionHeader {
                byte_order: self.byte_order,
                version: read_u16(&body, self.byte_order),
            },
            0x00000001 => {
                let lt = read_u16(&body[8..10], self.byte_order) as u32;
                self.link_type = Some(LinkType::from(lt));
                PcapNgBlock::InterfaceDescription {
                    link_type: LinkType::from(lt),
                    snap_len: read_u32(&body[12..16], self.byte_order),
                }
            }
            0x00000006 => {
                let _if_id = read_u32(&body[0..4], self.byte_order);
                let ts_hi = read_u32(&body[4..8], self.byte_order) as u64;
                let ts_lo = read_u32(&body[8..12], self.byte_order) as u64;
                let cap_len = read_u32(&body[12..16], self.byte_order) as usize;
                let ts = Duration::new(ts_hi, (ts_lo / 1000) as u32);
                let data = body[20..20 + cap_len].to_vec();
                PcapNgBlock::EnhancedPacket { timestamp: ts, data }
            }
            _ => PcapNgBlock::Unknown { block_type, data: body },
        };
        Some(Ok(block))
    }
}

#[inline]
fn read_u16(buf: &[u8], endian: Endianness) -> u16 {
    match endian { Endianness::Big => u16::from_be_bytes([buf[0], buf[1]]), Endianness::Little => u16::from_le_bytes([buf[0], buf[1]]) }
}
#[inline]
fn read_u32(buf: &[u8], endian: Endianness) -> u32 {
    match endian { Endianness::Big => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), Endianness::Little => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) }
}
