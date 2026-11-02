//! pcap file reader.

use std::io::Read;
use std::time::Duration;

use super::types::{Endianness, LinkType, PcapHeader};
use super::PacketCaptureReader;

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
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid magic: 0x{magic:08X}"),
                ))
            }
        };
        let read_u32 = |off: usize| endian.read_u32(&hdr_buf[off..]);
        Ok(Self {
            reader,
            endian,
            header: PcapHeader {
                magic_number: magic,
                version_major: endian.read_u16(&hdr_buf[4..]),
                version_minor: endian.read_u16(&hdr_buf[6..]),
                thiszone: read_u32(8) as i32,
                sigfigs: read_u32(12),
                snaplen: read_u32(16),
                network: read_u32(20),
            },
        })
    }

    pub fn header(&self) -> &PcapHeader {
        &self.header
    }
    pub fn link_type(&self) -> LinkType {
        LinkType::from_dlt(self.header.network as i32)
    }
}

impl<R: Read> Iterator for PcapReader<R> {
    type Item = Result<(Duration, Vec<u8>), std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut rec_hdr = [0u8; 16];
        match self.reader.read_exact(&mut rec_hdr) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        }
        let ts_sec = self.endian.read_u32(&rec_hdr[0..]);
        let ts_usec = self.endian.read_u32(&rec_hdr[4..]);
        let incl_len = self.endian.read_u32(&rec_hdr[8..]) as usize;

        // Defense against corrupted or crafted headers: never pre-allocate
        // based on the untrusted `incl_len` (a bogus 0xFFFFFFFF would attempt
        // a ~4 GB zeroed allocation before the first read fails). Read
        // incrementally instead so memory grows only as bytes actually
        // arrive, then require the full record to be present.
        let mut data = Vec::new();
        let read_result = {
            let mut limited = (&mut self.reader).take(incl_len as u64);
            limited.read_to_end(&mut data)
        };
        if let Err(e) = read_result {
            return Some(Err(e));
        }
        if data.len() != incl_len {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "truncated pcap record: expected {incl_len} bytes, got {}",
                    data.len()
                ),
            )));
        }
        Some(Ok((
            Duration::new(ts_sec as u64, 0) + Duration::from_micros(ts_usec as u64),
            data,
        )))
    }
}

impl<R: Read> PacketCaptureReader for PcapReader<R> {
    type Error = std::io::Error;

    fn link_type(&self) -> Option<LinkType> {
        Some(self.link_type())
    }

    fn next_packet(&mut self) -> Option<Result<(std::time::Duration, Vec<u8>), Self::Error>> {
        self.next()
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
    fn read_pcap_dlt_raw_12() {
        // Regression: DLT_RAW is 12 on most platforms; the file-level
        // LINKTYPE is 101. Both must map to LinkType::Raw.
        for network in [12u32, 101] {
            let mut data = make_pcap_file(&[]);
            data[20..24].copy_from_slice(&network.to_be_bytes());
            let reader = PcapReader::from_bytes(data).unwrap();
            assert_eq!(reader.link_type(), LinkType::Raw, "network={network}");
        }
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

    fn make_le_pcap_file(packets: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        for pkt in packets {
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            data.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            data.extend_from_slice(pkt);
        }
        data
    }

    #[test]
    fn read_little_endian_pcap() {
        let packets: Vec<&[u8]> = vec![&[0xAA, 0xBB]];
        let data = make_le_pcap_file(&packets);
        let reader = PcapReader::from_bytes(data).unwrap();
        assert_eq!(reader.header().network, 1);
        let results: Vec<_> = reader.collect();
        assert_eq!(results[0].as_ref().unwrap().1, &[0xAA, 0xBB]);
    }

    #[test]
    fn read_pcap_large_microsecond_timestamp_does_not_overflow() {
        let mut data = make_pcap_file(&[]);
        data.extend_from_slice(&0u32.to_be_bytes()); // ts_sec
        data.extend_from_slice(&5_000_000u32.to_be_bytes()); // ts_usec
        data.extend_from_slice(&1u32.to_be_bytes()); // incl_len
        data.extend_from_slice(&1u32.to_be_bytes()); // orig_len
        data.push(0xAA);

        let reader = PcapReader::from_bytes(data).unwrap();
        let results: Vec<_> = reader.collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn read_pcap_bad_magic() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(PcapReader::from_bytes(data).is_err());
    }

    #[test]
    fn read_pcap_huge_incl_len_returns_error_not_oom() {
        // Regression: a crafted incl_len used to trigger a ~4 GB pre-allocation
        // before the read failed. It must surface as a plain I/O error instead.
        let mut data = make_pcap_file(&[]);
        data.extend_from_slice(&0u32.to_be_bytes()); // ts_sec
        data.extend_from_slice(&0u32.to_be_bytes()); // ts_usec
        data.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // incl_len
        data.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // orig_len
        let reader = PcapReader::from_bytes(data).unwrap();
        let results: Vec<_> = reader.collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0], Err(_)));
    }
}
