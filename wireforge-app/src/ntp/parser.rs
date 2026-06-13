//! NTPv4 packet parser (RFC 5905).

use core::time::Duration;

use super::types::{NtpLeapIndicator, NtpMode};

pub const NTP_PACKET_LEN: usize = 48;

/// Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_EPOCH_DELTA: u32 = 2_208_988_800;

#[inline]
fn read_u32be(buf: &[u8]) -> u32 { u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) }

/// Zero-copy NTP packet parser.
#[derive(Debug, Clone)]
pub struct NtpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> NtpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < NTP_PACKET_LEN { return None; }
        Some(Self { buf })
    }

    #[inline] pub fn leap(&self) -> NtpLeapIndicator { NtpLeapIndicator::from(self.buf[0] >> 6) }
    #[inline] pub fn version(&self) -> u8 { (self.buf[0] >> 3) & 0x07 }
    #[inline] pub fn mode(&self) -> NtpMode { NtpMode::from(self.buf[0] & 0x07) }
    #[inline] pub fn stratum(&self) -> u8 { self.buf[1] }
    #[inline] pub fn poll_interval(&self) -> i8 { self.buf[2] as i8 }
    #[inline] pub fn precision(&self) -> i8 { self.buf[3] as i8 }
    #[inline] pub fn root_delay(&self) -> Duration { ntp_short_to_duration(read_u32be(&self.buf[4..8])) }
    #[inline] pub fn root_dispersion(&self) -> Duration { ntp_short_to_duration(read_u32be(&self.buf[8..12])) }
    #[inline] pub fn reference_id(&self) -> [u8; 4] { [self.buf[12], self.buf[13], self.buf[14], self.buf[15]] }
    #[inline] pub fn reference_timestamp(&self) -> Option<Duration> { ntp_timestamp_to_duration(read_u32be(&self.buf[16..20]), read_u32be(&self.buf[20..24])) }
    #[inline] pub fn origin_timestamp(&self) -> Option<Duration> { ntp_timestamp_to_duration(read_u32be(&self.buf[24..28]), read_u32be(&self.buf[28..32])) }
    #[inline] pub fn receive_timestamp(&self) -> Option<Duration> { ntp_timestamp_to_duration(read_u32be(&self.buf[32..36]), read_u32be(&self.buf[36..40])) }
    #[inline] pub fn transmit_timestamp(&self) -> Option<Duration> { ntp_timestamp_to_duration(read_u32be(&self.buf[40..44]), read_u32be(&self.buf[44..48])) }
}

/// Convert NTP short format (32-bit: 16s + 16 fraction) to Duration.
fn ntp_short_to_duration(val: u32) -> Duration {
    let secs = (val >> 16) as u64;
    let frac = (val & 0xFFFF) as u64;
    Duration::new(secs, (frac * 1_000_000_000 / 65536) as u32)
}

/// Convert NTP timestamp (64-bit: 32s + 32 fraction) to Duration since Unix epoch.
fn ntp_timestamp_to_duration(seconds: u32, fraction: u32) -> Option<Duration> {
    if seconds == 0 && fraction == 0 { return None; }
    let secs = seconds.saturating_sub(NTP_EPOCH_DELTA) as u64;
    let nanos = ((fraction as u64) * 1_000_000_000 >> 32) as u32;
    Some(Duration::new(secs, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ntp_client() {
        let mut data = [0u8; 48];
        data[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
        data[1] = 0;    // stratum=0 (unspecified)

        let pkt = NtpPacket::new(&data).unwrap();
        assert_eq!(pkt.leap(), NtpLeapIndicator::NoWarning);
        assert_eq!(pkt.version(), 3);
        assert_eq!(pkt.mode(), NtpMode::Client);
        assert_eq!(pkt.stratum(), 0);
    }

    #[test]
    fn parse_ntp_server() {
        let mut data = [0u8; 48];
        data[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
        data[1] = 2;    // stratum=2

        let pkt = NtpPacket::new(&data).unwrap();
        assert_eq!(pkt.version(), 4);
        assert_eq!(pkt.mode(), NtpMode::Server);
        assert_eq!(pkt.stratum(), 2);
    }

    #[test]
    fn parse_ntp_too_short() {
        assert!(NtpPacket::new(&[]).is_none());
        assert!(NtpPacket::new(&[0u8; 47]).is_none());
        assert!(NtpPacket::new(&[0u8; 48]).is_some());
    }

    #[test]
    fn ntp_timestamp_zero_returns_none() {
        let data = [0u8; 48];
        let pkt = NtpPacket::new(&data).unwrap();
        assert_eq!(pkt.transmit_timestamp(), None);
    }
}
