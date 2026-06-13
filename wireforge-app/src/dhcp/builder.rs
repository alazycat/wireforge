//! DHCPv4 message builder (RFC 2131/2132).

use super::parser::DHCP_MIN_LEN;
use super::types::DhcpOption;

const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

pub struct DhcpPacketBuilder {
    buf: Vec<u8>,
    options: Vec<u8>,
}

impl Default for DhcpPacketBuilder {
    fn default() -> Self { Self::new() }
}

impl DhcpPacketBuilder {
    pub fn new() -> Self {
        let mut buf = vec![0u8; DHCP_MIN_LEN];
        buf[0] = 1; // op=BOOTREQUEST
        buf[1] = 1; // htype=Ethernet
        buf[2] = 6; // hlen=6
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
        Self { buf, options: Vec::new() }
    }

    pub fn discover() -> Self { let mut s = Self::new(); s.options.push(53); s.options.push(1); s.options.push(1); s }
    pub fn request() -> Self { let mut s = Self::new(); s.options.push(53); s.options.push(1); s.options.push(3); s }
    pub fn offer() -> Self { let mut s = Self::new(); s.buf[0] = 2; s.options.push(53); s.options.push(1); s.options.push(2); s }
    pub fn ack() -> Self { let mut s = Self::new(); s.buf[0] = 2; s.options.push(53); s.options.push(1); s.options.push(5); s }

    pub fn op(mut self, v: u8) -> Self { self.buf[0] = v; self }
    pub fn htype(mut self, v: u8) -> Self { self.buf[1] = v; self }
    pub fn hlen(mut self, v: u8) -> Self { self.buf[2] = v; self }
    pub fn hops(mut self, v: u8) -> Self { self.buf[3] = v; self }
    pub fn xid(mut self, v: u32) -> Self { self.buf[4..8].copy_from_slice(&v.to_be_bytes()); self }
    pub fn secs(mut self, v: u16) -> Self { self.buf[8..10].copy_from_slice(&v.to_be_bytes()); self }
    pub fn flags(mut self, v: u16) -> Self { self.buf[10..12].copy_from_slice(&v.to_be_bytes()); self }
    pub fn yiaddr(mut self, ip: [u8; 4]) -> Self { self.buf[16..20].copy_from_slice(&ip); self }
    pub fn siaddr(mut self, ip: [u8; 4]) -> Self { self.buf[20..24].copy_from_slice(&ip); self }
    pub fn giaddr(mut self, ip: [u8; 4]) -> Self { self.buf[24..28].copy_from_slice(&ip); self }
    pub fn chaddr(mut self, mac: &[u8; 6]) -> Self { self.buf[28..34].copy_from_slice(mac); self }

    pub fn add_option(mut self, opt: &DhcpOption) -> Self {
        match opt {
            DhcpOption::SubnetMask(ip) => { self.options.push(1); self.options.push(4); self.options.extend_from_slice(&ip.octets()); }
            DhcpOption::Router(ips) => { self.options.push(3); self.options.push((ips.len() * 4) as u8); for ip in ips { self.options.extend_from_slice(&ip.octets()); } }
            DhcpOption::DnsServer(ips) => { self.options.push(6); self.options.push((ips.len() * 4) as u8); for ip in ips { self.options.extend_from_slice(&ip.octets()); } }
            DhcpOption::HostName(s) => { self.options.push(12); self.options.push(s.len() as u8); self.options.extend_from_slice(s.as_bytes()); }
            DhcpOption::DomainName(s) => { self.options.push(15); self.options.push(s.len() as u8); self.options.extend_from_slice(s.as_bytes()); }
            DhcpOption::BroadcastAddr(ip) => { self.options.push(28); self.options.push(4); self.options.extend_from_slice(&ip.octets()); }
            DhcpOption::RequestedIp(ip) => { self.options.push(50); self.options.push(4); self.options.extend_from_slice(&ip.octets()); }
            DhcpOption::LeaseTime(t) => { self.options.push(51); self.options.push(4); self.options.extend_from_slice(&t.to_be_bytes()); }
            DhcpOption::ServerId(ip) => { self.options.push(54); self.options.push(4); self.options.extend_from_slice(&ip.octets()); }
            DhcpOption::ParameterList(params) => { self.options.push(55); self.options.push(params.len() as u8); self.options.extend_from_slice(params); }
            DhcpOption::End => {}
            _ => {}
        }
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        self.options.push(0xff); // End option
        self.buf.extend_from_slice(&self.options);
        self.buf
    }
}
