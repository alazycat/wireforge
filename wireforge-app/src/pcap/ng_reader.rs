//! pcapng file reader.

use std::io::Read;
use std::time::Duration;

use super::types::{Endianness, LinkType, PcapNgBlock};
use super::PacketCaptureReader;

pub struct PcapNgReader<R: Read> {
    reader: R,
    link_type: Option<LinkType>,
    byte_order: Endianness,
}

impl<R: Read> PcapNgReader<R> {
    pub fn new(mut reader: R) -> Result<Self, std::io::Error> {
        // The section header starts with block type, total length, and the
        // byte-order magic that determines how every field is decoded.
        let mut shb = [0u8; 12];
        reader.read_exact(&mut shb)?;
        let block_type = u32::from_be_bytes([shb[0], shb[1], shb[2], shb[3]]);
        if block_type != 0x0A0D0D0A {
            return Err(invalid_data("pcapng section header block not found"));
        }
        let byte_order = match u32::from_be_bytes([shb[8], shb[9], shb[10], shb[11]]) {
            0x1A2B3C4D => Endianness::Big,
            0x4D3C2B1A => Endianness::Little,
            _ => return Err(invalid_data("invalid pcapng byte-order magic")),
        };
        let block_len = byte_order.read_u32(&shb[4..]) as usize;
        if block_len < 28 {
            return Err(invalid_data("pcapng section header block too short"));
        }
        // Consume the rest of the section header, including the trailing length.
        let mut rest = vec![0u8; block_len - 12];
        reader.read_exact(&mut rest)?;
        let trailing = byte_order.read_u32(&rest[rest.len() - 4..]) as usize;
        if trailing != block_len {
            return Err(invalid_data("pcapng section header length mismatch"));
        }
        Ok(Self {
            reader,
            link_type: None,
            byte_order,
        })
    }

    pub fn link_type(&self) -> Option<LinkType> {
        self.link_type
    }
}

impl<R: Read> PacketCaptureReader for PcapNgReader<R> {
    type Error = std::io::Error;

    fn link_type(&self) -> Option<LinkType> {
        self.link_type
    }

    fn next_packet(&mut self) -> Option<Result<(std::time::Duration, Vec<u8>), Self::Error>> {
        loop {
            match self.next()? {
                Ok(PcapNgBlock::EnhancedPacket { timestamp, data }) => {
                    return Some(Ok((timestamp, data)));
                }
                Ok(_) => continue, // skip non-packet blocks
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

impl<R: Read> Iterator for PcapNgReader<R> {
    type Item = Result<PcapNgBlock, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut hdr = [0u8; 8];
        match self.reader.read_exact(&mut hdr) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        }
        let block_type = self.byte_order.read_u32(&hdr[0..]);
        let block_len = self.byte_order.read_u32(&hdr[4..]) as usize;
        if block_len < 12 {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block too short",
            )));
        }
        let body_len = block_len - 12;
        let mut body = vec![0u8; body_len];
        if let Err(e) = self.reader.read_exact(&mut body) {
            return Some(Err(e));
        }
        // Read trailing block length
        let mut tail = [0u8; 4];
        if let Err(e) = self.reader.read_exact(&mut tail) {
            return Some(Err(e));
        }

        let block = match block_type {
            0x0A0D0D0A => {
                if body.len() < 6 {
                    return Some(Err(invalid_data("truncated section header block")));
                }
                PcapNgBlock::SectionHeader {
                    byte_order: self.byte_order,
                    version: self.byte_order.read_u16(&body[4..]),
                }
            }
            0x00000001 => {
                if body.len() < 8 {
                    return Some(Err(invalid_data("truncated interface description block")));
                }
                let lt = self.byte_order.read_u16(&body) as u32;
                self.link_type = Some(LinkType::from_dlt(lt as i32));
                PcapNgBlock::InterfaceDescription {
                    link_type: LinkType::from_dlt(lt as i32),
                    snap_len: self.byte_order.read_u32(&body[4..]),
                }
            }
            0x00000006 => {
                if body.len() < 20 {
                    return Some(Err(invalid_data("truncated enhanced packet block")));
                }
                let _if_id = self.byte_order.read_u32(&body);
                let ts_hi = self.byte_order.read_u32(&body[4..]) as u64;
                let ts_lo = self.byte_order.read_u32(&body[8..]) as u64;
                let cap_len = self.byte_order.read_u32(&body[12..]) as usize;
                let Some(end) = 20usize.checked_add(cap_len) else {
                    return Some(Err(invalid_data(
                        "enhanced packet block capture length overflow",
                    )));
                };
                let Some(packet) = body.get(20..end) else {
                    return Some(Err(invalid_data(
                        "enhanced packet block capture length exceeds block",
                    )));
                };
                // Default if_tsresol is 10^-6: timestamp ticks are microseconds.
                let ts = Duration::from_micros((ts_hi << 32) | ts_lo);
                PcapNgBlock::EnhancedPacket {
                    timestamp: ts,
                    data: packet.to_vec(),
                }
            }
            _ => PcapNgBlock::Unknown {
                block_type,
                data: body,
            },
        };
        Some(Ok(block))
    }
}

fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::PcapNgWriter;
    use std::io::Cursor;

    fn wrap_block(block_type: u32, body: &[u8]) -> Vec<u8> {
        let len = (12 + body.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&block_type.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&len.to_be_bytes());
        out
    }

    fn section_header() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x1A2B3C4Du32.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&u64::MAX.to_be_bytes());
        wrap_block(0x0A0D0D0A, &body)
    }

    #[test]
    fn writer_reader_roundtrip() {
        let mut buf = Vec::new();
        {
            let mut writer = PcapNgWriter::new(&mut buf, LinkType::Ethernet).unwrap();
            writer
                .write_epb(Duration::from_micros(1_500_000), &[0xAA, 0xBB, 0xCC])
                .unwrap();
        }

        let mut reader = PcapNgReader::new(Cursor::new(buf)).unwrap();
        let (ts, data) = reader.next_packet().unwrap().unwrap();
        assert_eq!(ts, Duration::from_micros(1_500_000));
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(reader.link_type(), Some(LinkType::Ethernet));
    }

    fn wrap_le_block(block_type: u32, body: &[u8]) -> Vec<u8> {
        let len = (12 + body.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&block_type.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&len.to_le_bytes());
        out
    }

    #[test]
    fn reads_little_endian_pcapng() {
        let mut data = Vec::new();

        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&u64::MAX.to_le_bytes());
        data.extend_from_slice(&wrap_le_block(0x0A0D0D0A, &shb));

        let mut idb = Vec::new();
        idb.extend_from_slice(&1u16.to_le_bytes()); // Ethernet
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&wrap_le_block(1, &idb));

        let mut epb = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes()); // interface_id
        epb.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        epb.extend_from_slice(&1_500_000u32.to_le_bytes()); // ts_low
        epb.extend_from_slice(&3u32.to_le_bytes()); // captured_len
        epb.extend_from_slice(&3u32.to_le_bytes()); // original_len
        epb.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        epb.resize(24, 0);
        data.extend_from_slice(&wrap_le_block(6, &epb));

        let mut reader = PcapNgReader::new(Cursor::new(data)).unwrap();
        let (ts, packet) = reader.next_packet().unwrap().unwrap();
        assert_eq!(ts, Duration::from_micros(1_500_000));
        assert_eq!(packet, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(reader.link_type(), Some(LinkType::Ethernet));
    }

    #[test]
    fn truncated_interface_block_returns_error() {
        let mut data = section_header();
        data.extend_from_slice(&wrap_block(1, &[]));
        let mut reader = PcapNgReader::new(Cursor::new(data)).unwrap();
        assert!(matches!(reader.next(), Some(Err(_))));
    }

    #[test]
    fn truncated_enhanced_packet_returns_error() {
        let mut data = section_header();
        data.extend_from_slice(&wrap_block(6, &[0u8; 4]));
        let mut reader = PcapNgReader::new(Cursor::new(data)).unwrap();
        assert!(matches!(reader.next(), Some(Err(_))));
    }

    #[test]
    fn enhanced_packet_with_oversized_capture_length_returns_error() {
        let mut body = vec![0u8; 20];
        // captured length claims 64 bytes but no packet bytes follow
        body[12..16].copy_from_slice(&64u32.to_be_bytes());
        let mut data = section_header();
        data.extend_from_slice(&wrap_block(6, &body));
        let mut reader = PcapNgReader::new(Cursor::new(data)).unwrap();
        assert!(matches!(reader.next(), Some(Err(_))));
    }
}
