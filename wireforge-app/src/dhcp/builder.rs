//! DHCPv4 message builder (RFC 2131/2132).

use core::net::Ipv4Addr;

use super::parser::DHCP_MIN_LEN;
use super::types::{DhcpMessageType, DhcpOption};

const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

pub struct DhcpPacketBuilder {
    buf: Vec<u8>,
    options: Vec<u8>,
}

impl Default for DhcpPacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpPacketBuilder {
    pub fn new() -> Self {
        let mut buf = vec![0u8; DHCP_MIN_LEN];
        buf[0] = 1; // op=BOOTREQUEST
        buf[1] = 1; // htype=Ethernet
        buf[2] = 6; // hlen=6
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE.to_be_bytes());
        Self {
            buf,
            options: Vec::new(),
        }
    }

    pub fn discover() -> Self {
        Self::with_message_type(1, 1)
    }
    pub fn request() -> Self {
        Self::with_message_type(1, 3)
    }
    pub fn offer() -> Self {
        Self::with_message_type(2, 2)
    }
    pub fn ack() -> Self {
        Self::with_message_type(2, 5)
    }

    /// Start a message with the BOOTP op and DHCP message type option.
    fn with_message_type(op: u8, message_type: u8) -> Self {
        let mut s = Self::new();
        s.buf[0] = op;
        s.push_option(53, &[message_type]);
        s
    }

    pub fn op(mut self, v: u8) -> Self {
        self.buf[0] = v;
        self
    }
    pub fn htype(mut self, v: u8) -> Self {
        self.buf[1] = v;
        self
    }
    pub fn hlen(mut self, v: u8) -> Self {
        self.buf[2] = v;
        self
    }
    pub fn hops(mut self, v: u8) -> Self {
        self.buf[3] = v;
        self
    }
    pub fn xid(mut self, v: u32) -> Self {
        self.buf[4..8].copy_from_slice(&v.to_be_bytes());
        self
    }
    pub fn secs(mut self, v: u16) -> Self {
        self.buf[8..10].copy_from_slice(&v.to_be_bytes());
        self
    }
    pub fn flags(mut self, v: u16) -> Self {
        self.buf[10..12].copy_from_slice(&v.to_be_bytes());
        self
    }
    pub fn yiaddr(mut self, ip: [u8; 4]) -> Self {
        self.buf[16..20].copy_from_slice(&ip);
        self
    }
    pub fn siaddr(mut self, ip: [u8; 4]) -> Self {
        self.buf[20..24].copy_from_slice(&ip);
        self
    }
    pub fn giaddr(mut self, ip: [u8; 4]) -> Self {
        self.buf[24..28].copy_from_slice(&ip);
        self
    }
    pub fn chaddr(mut self, mac: &[u8; 6]) -> Self {
        self.buf[28..34].copy_from_slice(mac);
        self
    }

    pub fn add_option(mut self, opt: &DhcpOption) -> Self {
        match opt {
            DhcpOption::SubnetMask(ip) => self.push_option(1, &ip.octets()),
            DhcpOption::Router(ips) => self.push_option(3, &encode_ipv4_list(ips)),
            DhcpOption::DnsServer(ips) => self.push_option(6, &encode_ipv4_list(ips)),
            DhcpOption::HostName(s) => self.push_option(12, s.as_bytes()),
            DhcpOption::DomainName(s) => self.push_option(15, s.as_bytes()),
            DhcpOption::BroadcastAddr(ip) => self.push_option(28, &ip.octets()),
            DhcpOption::RequestedIp(ip) => self.push_option(50, &ip.octets()),
            DhcpOption::LeaseTime(t) => self.push_option(51, &t.to_be_bytes()),
            DhcpOption::MessageType(mt) => self.push_option(53, &[u8::from(*mt)]),
            DhcpOption::ServerId(ip) => self.push_option(54, &ip.octets()),
            DhcpOption::ParameterList(params) => self.push_option(55, params),
            DhcpOption::RenewalTime(t) => self.push_option(58, &t.to_be_bytes()),
            DhcpOption::RebindingTime(t) => self.push_option(59, &t.to_be_bytes()),
            DhcpOption::Unknown { code, data } => self.push_option(*code, data),
            DhcpOption::End => {}
        }
        self
    }

    /// Append a code/length/value option.
    fn push_option(&mut self, code: u8, data: &[u8]) {
        self.options.push(code);
        self.options.push(data.len() as u8);
        self.options.extend_from_slice(data);
    }

    pub fn build(mut self) -> Vec<u8> {
        self.options.push(0xff); // End option
        self.buf.extend_from_slice(&self.options);
        self.buf
    }
}

/// Encode a list of IPv4 addresses as consecutive 4-byte octets.
fn encode_ipv4_list(ips: &[Ipv4Addr]) -> Vec<u8> {
    ips.iter().flat_map(|ip| ip.octets()).collect()
}
