//! DHCPv4 message parser (RFC 2131/2132).

use core::net::Ipv4Addr;

use super::types::{DhcpMessageType, DhcpOption};
use wireforge_core::util::{read_u16be, read_u32be};

const DHCP_MAGIC_COOKIE: u32 = 0x63825363;
pub const DHCP_MIN_LEN: usize = 240;

/// Zero-copy DHCP packet parser.
#[derive(Debug, Clone)]
pub struct DhcpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> DhcpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < DHCP_MIN_LEN { return None; }
        if read_u32be(&buf[236..240]) != DHCP_MAGIC_COOKIE { return None; }
        Some(Self { buf })
    }

    #[inline] pub fn op(&self) -> u8 { self.buf[0] }
    #[inline] pub fn htype(&self) -> u8 { self.buf[1] }
    #[inline] pub fn hlen(&self) -> u8 { self.buf[2] }
    #[inline] pub fn hops(&self) -> u8 { self.buf[3] }
    #[inline] pub fn xid(&self) -> u32 { read_u32be(&self.buf[4..8]) }
    #[inline] pub fn secs(&self) -> u16 { read_u16be(&self.buf[8..10]) }
    #[inline] pub fn flags(&self) -> u16 { read_u16be(&self.buf[10..12]) }
    #[inline] pub fn broadcast(&self) -> bool { self.flags() & 0x8000 != 0 }
    #[inline] pub fn ciaddr(&self) -> Ipv4Addr { ip4(&self.buf[12..16]) }
    #[inline] pub fn yiaddr(&self) -> Ipv4Addr { ip4(&self.buf[16..20]) }
    #[inline] pub fn siaddr(&self) -> Ipv4Addr { ip4(&self.buf[20..24]) }
    #[inline] pub fn giaddr(&self) -> Ipv4Addr { ip4(&self.buf[24..28]) }
    #[inline] pub fn chaddr(&self) -> &[u8] { &self.buf[28..44] }
    #[inline] pub fn sname(&self) -> &[u8] { &self.buf[44..108] }
    #[inline] pub fn file(&self) -> &[u8] { &self.buf[108..236] }
    #[inline] pub fn magic_cookie(&self) -> u32 { read_u32be(&self.buf[236..240]) }

    pub fn options(&self) -> DhcpOptionIter<'a> {
        let buf = self.buf;
        DhcpOptionIter {
            buf,
            pos: 240,
            file_buf: &buf[108..236],
            sname_buf: &buf[44..108],
            overload: self._find_overload(),
            phase: 0,
        }
    }

    fn _find_overload(&self) -> u8 {
        let mut pos = 240usize;
        while pos + 2 <= self.buf.len() {
            let code = self.buf[pos];
            if code == 0xff { break; }
            if code == 0 { pos += 1; continue; }
            if pos + 1 >= self.buf.len() { break; }
            let len = self.buf[pos + 1] as usize;
            if code == 52 && len >= 1 && pos + 2 < self.buf.len() {
                return self.buf[pos + 2];
            }
            pos += 2 + len;
        }
        0
    }

    pub fn message_type(&self) -> Option<DhcpMessageType> {
        for opt in self.options() {
            if let DhcpOption::MessageType(mt) = opt { return Some(mt); }
            if matches!(opt, DhcpOption::End) { break; }
        }
        None
    }
}

fn ip4(b: &[u8]) -> Ipv4Addr { Ipv4Addr::new(b[0], b[1], b[2], b[3]) }

pub struct DhcpOptionIter<'a> {
    buf: &'a [u8],
    pos: usize,
    file_buf: &'a [u8],
    sname_buf: &'a [u8],
    overload: u8,
    phase: u8,
}

impl<'a> Iterator for DhcpOptionIter<'a> {
    type Item = DhcpOption;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let data = match self.phase {
                0 => {
                    if self.pos >= self.buf.len() { self.phase = 1; self.pos = 0; continue; }
                    &self.buf[self.pos..]
                }
                1 => {
                    if self.overload & 1 == 0 || self.pos >= self.file_buf.len() { self.phase = 2; self.pos = 0; continue; }
                    &self.file_buf[self.pos..]
                }
                2 => {
                    if self.overload & 2 == 0 || self.pos >= self.sname_buf.len() { return None; }
                    &self.sname_buf[self.pos..]
                }
                _ => return None,
            };
            if data.is_empty() { return None; }
            let code = data[0];
            if code == 0xff { return None; }
            if code == 0 { self.pos += 1; continue; }
            if data.len() < 2 { return None; }
            let len = data[1] as usize;
            if data.len() < 2 + len { self.pos += 2 + data.len().saturating_sub(2); continue; }
            let val = &data[2..2 + len];
            let opt = parse_option(code, val);
            self.pos += 2 + len;
            return Some(opt);
        }
    }
}

fn parse_option(code: u8, data: &[u8]) -> DhcpOption {
    match code {
        1 => DhcpOption::SubnetMask(ip4(&data[..4.min(data.len())])),
        3 => DhcpOption::Router(parse_ip_list(data)),
        6 => DhcpOption::DnsServer(parse_ip_list(data)),
        12 => DhcpOption::HostName(String::from_utf8_lossy(data).into_owned()),
        15 => DhcpOption::DomainName(String::from_utf8_lossy(data).into_owned()),
        28 => DhcpOption::BroadcastAddr(ip4(&data[..4.min(data.len())])),
        50 => DhcpOption::RequestedIp(ip4(&data[..4.min(data.len())])),
        51 => DhcpOption::LeaseTime(read_u32be(&data[..4.min(data.len())])),
        53 => DhcpOption::MessageType(DhcpMessageType::from(data.first().copied().unwrap_or(0))),
        54 => DhcpOption::ServerId(ip4(&data[..4.min(data.len())])),
        55 => DhcpOption::ParameterList(data.to_vec()),
        58 => DhcpOption::RenewalTime(read_u32be(&data[..4.min(data.len())])),
        59 => DhcpOption::RebindingTime(read_u32be(&data[..4.min(data.len())])),
        _ => DhcpOption::Unknown { code, data: data.to_vec() },
    }
}

fn parse_ip_list(data: &[u8]) -> Vec<Ipv4Addr> {
    data.chunks(4).filter(|c| c.len() == 4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::builder::DhcpPacketBuilder;

    #[test]
    fn parse_dhcp_discover() {
        let data = DhcpPacketBuilder::discover()
            .xid(0x12345678)
            .chaddr(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .build();

        let pkt = DhcpPacket::new(&data).unwrap();
        assert_eq!(pkt.op(), 1);
        assert_eq!(pkt.xid(), 0x12345678);
        assert_eq!(pkt.magic_cookie(), 0x63825363);
        assert_eq!(pkt.message_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn parse_dhcp_too_short() {
        assert!(DhcpPacket::new(&[]).is_none());
        assert!(DhcpPacket::new(&[0u8; 239]).is_none());
    }

    #[test]
    fn parse_dhcp_bad_cookie() {
        let mut data = vec![0u8; 240];
        data[236..240].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        assert!(DhcpPacket::new(&data).is_none());
    }

    #[test]
    fn dhcp_offer_with_options() {
        let server_ip = [192u8, 168, 1, 1];
        let client_ip = [192u8, 168, 1, 100];
        let data = DhcpPacketBuilder::offer()
            .xid(0x42)
            .yiaddr(client_ip)
            .siaddr(server_ip)
            .add_option(&DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)))
            .add_option(&DhcpOption::LeaseTime(86400))
            .add_option(&DhcpOption::ServerId(Ipv4Addr::new(192, 168, 1, 1)))
            .build();

        let pkt = DhcpPacket::new(&data).unwrap();
        assert_eq!(pkt.op(), 2);
        assert_eq!(pkt.message_type(), Some(DhcpMessageType::Offer));
        assert_eq!(pkt.yiaddr(), Ipv4Addr::new(192, 168, 1, 100));

        let opts: Vec<_> = pkt.options().collect();
        assert!(opts.iter().any(|o| matches!(o, DhcpOption::SubnetMask(_))));
        assert!(opts.iter().any(|o| matches!(o, DhcpOption::LeaseTime(86400))));
    }
}
