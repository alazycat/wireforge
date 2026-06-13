//! MQTT packet parser.

use std::str;

use super::types::{MqttPacketType, MqttProperty, QoS};

/// Decode MQTT variable-length remaining length (1-4 bytes).
pub fn read_remaining_length(buf: &[u8]) -> Option<(u32, usize)> {
    let mut value: u32 = 0;
    let mut multiplier = 1u32;
    for (i, &byte) in buf.iter().enumerate() {
        value += (byte as u32 & 0x7F) * multiplier;
        if byte & 0x80 == 0 { return Some((value, i + 1)); }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 { return None; }
    }
    None
}

pub fn write_remaining_length(len: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = len;
    loop {
        let mut byte = (v % 128) as u8;
        v /= 128;
        if v > 0 { byte |= 0x80; }
        out.push(byte);
        if v == 0 { break; }
    }
    out
}

/// Parsed MQTT packet.
pub struct MqttPacket<'a> {
    buf: &'a [u8],
    header_len: usize,
    remaining_len: u32,
}

impl<'a> MqttPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.is_empty() { return None; }
        let (remaining_len, header_len) = read_remaining_length(&buf[1..])?;
        Some(Self { buf, header_len: 1 + header_len, remaining_len })
    }

    pub fn packet_type(&self) -> MqttPacketType { MqttPacketType::from(self.buf[0]) }
    pub fn flags(&self) -> u8 { self.buf[0] & 0x0F }
    pub fn qos(&self) -> QoS { QoS::from(self.flags()) }
    pub fn remaining_length(&self) -> u32 { self.remaining_len }
    pub fn variable_header(&self) -> &'a [u8] { &self.buf[self.header_len..] }
    pub fn payload(&self) -> &'a [u8] {
        let vh = self.variable_header();
        let vh_len = self._vh_len();
        &vh[vh_len..]
    }

    fn _vh_len(&self) -> usize {
        match self.packet_type() {
            MqttPacketType::Connect => {
                let vh = self.variable_header();
                if vh.len() < 6 { return 0; }
                let plen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let mut pos = 2 + plen; // protocol name
                if pos + 4 > vh.len() { return pos; }
                pos += 1; // protocol level
                let flags = vh[pos]; pos += 1; // connect flags
                pos += 2; // keep_alive
                // MQTT 5.0 properties
                if vh[pos-4] == 5 { // protocol level 5
                    if let Some((_, plen)) = read_remaining_length(&vh[pos..]) { pos += plen; }
                }
                // client_id
                if pos + 2 > vh.len() { return pos; }
                let cid_len = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize;
                pos += 2 + cid_len;
                // will
                if flags & 0x04 != 0 && pos + 2 <= vh.len() {
                    // MQTT 5.0: will properties
                    if vh[2 + plen] == 5 {
                        if let Some((_, plen)) = read_remaining_length(&vh[pos..]) { pos += plen; }
                    }
                    if pos + 2 <= vh.len() {
                        let wt_len = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize;
                        pos += 2 + wt_len;
                        if pos + 2 <= vh.len() {
                            let wm_len = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize;
                            pos += 2 + wm_len;
                        }
                    }
                }
                // username
                if flags & 0x80 != 0 && pos + 2 <= vh.len() {
                    let ulen = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize;
                    pos += 2 + ulen;
                }
                // password
                if flags & 0x40 != 0 && pos + 2 <= vh.len() {
                    let plen = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize;
                    pos += 2 + plen;
                }
                pos
            }
            MqttPacketType::Connack => {
                let vh = self.variable_header();
                if vh.is_empty() { return 0; }
                let mut pos = 2; // session_present + return_code
                if vh.len() > 2 { // MQTT 5.0 properties
                    if let Some((_, plen)) = read_remaining_length(&vh[pos..]) { pos += plen; }
                }
                pos
            }
            MqttPacketType::Publish => {
                let vh = self.variable_header();
                if vh.len() < 2 { return 0; }
                let tlen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let mut pos = 2 + tlen;
                if self.qos() as u8 > 0 { pos += 2; } // packet_id
                pos
            }
            MqttPacketType::Subscribe => {
                let vh = self.variable_header();
                if vh.len() < 2 { return 0; }
                2 // packet_id only
            }
            _ => 0,
        }
    }

    pub fn message(&self) -> MqttMessage<'a> {
        let vh = self.variable_header();
        match self.packet_type() {
            MqttPacketType::Connect => {
                if vh.len() < 6 { return MqttMessage::Unknown { packet_type: MqttPacketType::Connect, data: vh }; }
                let plen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let proto = str::from_utf8(&vh[2..2+plen]).unwrap_or("");
                let level = vh[2+plen];
                let flags = vh[3+plen];
                let keep_alive = u16::from_be_bytes([vh[4+plen], vh[5+plen]]);
                let mut pos = 6 + plen;
                // MQTT 5 properties
                let properties = if level == 5 {
                    parse_properties(&vh[pos..]).unwrap_or_default()
                } else { vec![] };
                if level == 5 { if let Some((_, pl)) = read_remaining_length(&vh[pos..]) { pos += pl; } }
                // client_id
                let cid_len = if pos + 2 <= vh.len() { u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize } else { 0 };
                pos += 2;
                let client_id = str::from_utf8(&vh[pos..pos+cid_len]).unwrap_or("");
                pos += cid_len;
                // will
                let (will_topic, will_message) = if flags & 0x04 != 0 {
                    let mut wt = None; let mut wm = None;
                    if level == 5 { if let Some((_, pl)) = read_remaining_length(&vh[pos..]) { pos += pl; } }
                    if pos + 2 <= vh.len() { let wtl = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize; pos += 2; if pos+wtl <= vh.len() { wt = str::from_utf8(&vh[pos..pos+wtl]).ok(); pos += wtl; } }
                    if pos + 2 <= vh.len() { let wml = u16::from_be_bytes([vh[pos], vh[pos+1]]) as usize; pos += 2; if pos+wml <= vh.len() { wm = Some(&vh[pos..pos+wml]); pos += wml; } }
                    (wt, wm)
                } else { (None, None) };
                // username/password
                let username = if flags & 0x80 != 0 { if pos+2<=vh.len() { let ul = u16::from_be_bytes([vh[pos],vh[pos+1]]) as usize; pos+=2; str::from_utf8(&vh[pos..pos+ul]).ok() } else { None } } else { None };
                let password = if flags & 0x40 != 0 { if pos+2<=vh.len() { let pl = u16::from_be_bytes([vh[pos],vh[pos+1]]) as usize; pos+=2; Some(&vh[pos..pos+pl]) } else { None } } else { None };
                MqttMessage::Connect {
                    protocol_name: proto, protocol_level: level,
                    clean_start: flags & 0x02 != 0, keep_alive,
                    client_id, will_topic, will_message, username, password, properties,
                }
            }
            MqttPacketType::Publish => {
                if vh.len() < 2 { return MqttMessage::Unknown { packet_type: MqttPacketType::Publish, data: vh }; }
                let tlen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let topic = str::from_utf8(&vh[2..2+tlen]).unwrap_or("");
                let mut pos = 2 + tlen;
                let packet_id = if self.qos() as u8 > 0 && pos + 2 <= vh.len() { let id = u16::from_be_bytes([vh[pos], vh[pos+1]]); pos += 2; Some(id) } else { None };
                let payload = &vh[pos..];
                MqttMessage::Publish { topic, packet_id, payload }
            }
            MqttPacketType::Subscribe => {
                let packet_id = if vh.len() >= 2 { u16::from_be_bytes([vh[0], vh[1]]) } else { 0 };
                let topics = if vh.len() > 2 {
                    let data = &vh[2..];
                    let mut topics = Vec::new();
                    let mut p = 0;
                    while p + 3 <= data.len() {
                        let tl = u16::from_be_bytes([data[p], data[p+1]]) as usize;
                        p += 2;
                        if p + tl + 1 <= data.len() {
                            let tf = str::from_utf8(&data[p..p+tl]).unwrap_or("");
                            topics.push((tf, data[p+tl]));
                            p += tl + 1;
                        } else { break; }
                    }
                    topics
                } else { vec![] };
                MqttMessage::Subscribe { packet_id, topics }
            }
            _ => MqttMessage::Unknown { packet_type: self.packet_type(), data: vh },
        }
    }
}

fn parse_properties(data: &[u8]) -> Option<Vec<MqttProperty>> {
    let (prop_len, mut pos) = read_remaining_length(data)?;
    let end = (pos + prop_len as usize).min(data.len());
    let mut props = Vec::new();
    while pos < end {
        let id = data[pos]; pos += 1;
        match id {
            0x11 => { if pos+4<=end { props.push(MqttProperty::SessionExpiryInterval(u32::from_be_bytes([data[pos],data[pos+1],data[pos+2],data[pos+3]]))); pos+=4; } }
            0x27 => { if pos+4<=end { props.push(MqttProperty::MaximumPacketSize(u32::from_be_bytes([data[pos],data[pos+1],data[pos+2],data[pos+3]]))); pos+=4; } }
            0x23 => { if pos+2<=end { props.push(MqttProperty::TopicAlias(u16::from_be_bytes([data[pos],data[pos+1]]))); pos+=2; } }
            0x19 => { props.push(MqttProperty::RequestResponseInfo(data.get(pos).copied().unwrap_or(0) != 0)); pos += 1; }
            _ => { let mut v = vec![id]; while pos < end { v.push(data[pos]); pos += 1; } props.push(MqttProperty::Unknown(id, v)); }
        }
    }
    Some(props)
}

/// Parsed MQTT message (typed).
#[derive(Debug, Clone)]
pub enum MqttMessage<'a> {
    Connect {
        protocol_name: &'a str, protocol_level: u8, clean_start: bool, keep_alive: u16,
        client_id: &'a str, will_topic: Option<&'a str>, will_message: Option<&'a [u8]>,
        username: Option<&'a str>, password: Option<&'a [u8]>, properties: Vec<MqttProperty>,
    },
    Publish { topic: &'a str, packet_id: Option<u16>, payload: &'a [u8] },
    Subscribe { packet_id: u16, topics: Vec<(&'a str, u8)> },
    Unknown { packet_type: MqttPacketType, data: &'a [u8] },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_length_encoding() {
        assert_eq!(read_remaining_length(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_remaining_length(&[0x7F]).unwrap(), (127, 1));
        assert_eq!(read_remaining_length(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(read_remaining_length(&[0xFF, 0x7F]).unwrap(), (16383, 2));
        assert_eq!(write_remaining_length(128), vec![0x80, 0x01]);
        assert_eq!(write_remaining_length(127), vec![0x7F]);
    }

    #[test]
    fn parse_mqtt311_connect() {
        // MQTT 3.1.1 CONNECT: client_id="test"
        let mut data = vec![0x10u8]; // type=Connect
        // remaining length
        let mut payload = vec![0x00, 0x04, b'M', b'Q', b'T', b'T']; // proto name
        payload.push(4); // level=4 (3.1.1)
        payload.push(0x02); // flags: clean_start
        payload.extend_from_slice(&60u16.to_be_bytes()); // keep_alive
        payload.extend_from_slice(&[0x00, 0x04, b't', b'e', b's', b't']); // client_id
        data.extend_from_slice(&write_remaining_length(payload.len() as u32));
        data.extend_from_slice(&payload);

        let pkt = MqttPacket::parse(&data).unwrap();
        assert_eq!(pkt.packet_type(), MqttPacketType::Connect);
        match pkt.message() {
            MqttMessage::Connect { client_id, clean_start, keep_alive, .. } => {
                assert_eq!(client_id, "test"); assert!(clean_start); assert_eq!(keep_alive, 60);
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn parse_mqtt_publish() {
        let topic = b"test/topic";
        let payload = b"hello";
        let mut vh = vec![];
        vh.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        vh.extend_from_slice(topic);
        // QoS 0, no packet_id
        let mut data = vec![0x30u8]; // type=Publish, QoS=0
        data.extend_from_slice(&write_remaining_length((vh.len() + payload.len()) as u32));
        data.extend_from_slice(&vh);
        data.extend_from_slice(payload);

        let pkt = MqttPacket::parse(&data).unwrap();
        match pkt.message() {
            MqttMessage::Publish { topic: t, payload: p, .. } => {
                assert_eq!(t, "test/topic"); assert_eq!(p, b"hello");
            }
            _ => panic!("expected Publish"),
        }
    }
}
