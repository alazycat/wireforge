//! pcap file reader.

use std::io::Read;
use std::time::Duration;

use super::types::{Endianness, LinkType, PcapHeader};

#[inline]
fn read_u32(buf: &[u8], endian: Endianness) -> u32 {
    match endian { Endianness::Big => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), Endianness::Little => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) }
}

pub struct PcapReader<R: Read> {
    reader: R,
    header: PcapHeader,
    endian: Endianness,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut reader: R) -> Result<Self, std::io::Error> {
        let mut hdr_buf = [0u8; 24];
        reader.read_exact(&mut hdr_buf)?;
        let magic = u32::from_be_bytes([hdr_buf[0], hdr_buf[1], hdr_buf[2], hdr_buf[3]]);
        let endian = match magic {
            0xa1b2c3d4 => Endianness::Big,
            0xd4c3b2a1 => Endianness::Little,
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid magic: 0x{magic:08X}"))),
        };
        // Swap bytes if needed
        let read_u32 = |off: usize| -> u32 {
            let b = &hdr_buf[off..off+4];
            match endian { Endianness::Big => u32::from_be_bytes([b[0],b[1],b[2],b[3]]), Endianness::Little => u32::from_le_bytes([b[0],b[1],b[2],b[3]]) }
        };
        let read_u16 = |off: usize| -> u16 {
            let b = &hdr_buf[off..off+2];
            match endian { Endianness::Big => u16::from_be_bytes([b[0],b[1]]), Endianness::Little => u16::from_le_bytes([b[0],b[1]]) }
        };
        Ok(Self {
            reader,
            endian,
            header: PcapHeader {
                magic_number: magic,
                version_major: read_u16(4),
                version_minor: read_u16(6),
                thiszone: read_u32(8) as i32,
                sigfigs: read_u32(12),
                snaplen: read_u32(16),
                network: read_u32(20),
            },
        })
    }

    pub fn header(&self) -> &PcapHeader { &self.header }
    pub fn link_type(&self) -> LinkType { LinkType::from(self.header.network) }
}

impl<R: Read> Iterator for PcapReader<R> {
    type Item = Result<(Duration, Vec<u8>), std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut rec_hdr = [0u8; 16];
        match self.reader.read_exact(&mut rec_hdr) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e.into())),
        }
        let ts_sec = read_u32(&rec_hdr[0..4], self.endian);
        let ts_usec = read_u32(&rec_hdr[4..8], self.endian);
        let incl_len = read_u32(&rec_hdr[8..12], self.endian) as usize;

        let mut data = vec![0u8; incl_len];
        if let Err(e) = self.reader.read_exact(&mut data) {
            return Some(Err(e.into()));
        }
        Some(Ok((Duration::new(ts_sec as u64, ts_usec * 1000), data)))
    }
}

// Convenience: construct from in-memory bytes for testing.
impl PcapReader<std::io::Cursor<Vec<u8>>> {
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, std::io::Error> {
        Self::new(std::io::Cursor::new(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pcap_file(packets: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        // global header
        data.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes());
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[0u8; 8]); // thiszone + sigfigs
        data.extend_from_slice(&65535u32.to_be_bytes()); // snaplen
        data.extend_from_slice(&1u32.to_be_bytes()); // network=Ethernet
        for pkt in packets {
            data.extend_from_slice(&0u32.to_be_bytes()); // ts_sec
            data.extend_from_slice(&0u32.to_be_bytes()); // ts_usec
            data.extend_from_slice(&(pkt.len() as u32).to_be_bytes()); // incl_len
            data.extend_from_slice(&(pkt.len() as u32).to_be_bytes()); // orig_len
            data.extend_from_slice(pkt);
        }
        data
    }

    #[test]
    fn read_pcap_empty() {
        let data = make_pcap_file(&[]);
        let reader = PcapReader::from_bytes(data).unwrap();
        assert_eq!(reader.link_type(), LinkType::Ethernet);
        assert_eq!(reader.header().version_major, 2);
    }

    #[test]
    fn read_pcap_with_packets() {
        let packets: Vec<&[u8]> = vec![&[0xAA, 0xBB], &[0xCC, 0xDD, 0xEE]];
        let data = make_pcap_file(&packets);
        let reader = PcapReader::from_bytes(data).unwrap();
        let results: Vec<_> = reader.collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().1, &[0xAA, 0xBB]);
        assert_eq!(results[1].as_ref().unwrap().1, &[0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn read_pcap_bad_magic() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(PcapReader::from_bytes(data).is_err());
    }
}
