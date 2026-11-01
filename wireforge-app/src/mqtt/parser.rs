//! MQTT packet parser.

use std::str;

use super::types::{MqttPacketType, MqttProperty, QoS};

/// Decode MQTT variable-length remaining length (1-4 bytes).
pub fn read_remaining_length(buf: &[u8]) -> Option<(u32, usize)> {
    let mut value: u32 = 0;
    let mut multiplier = 1u32;
    for (i, &byte) in buf.iter().enumerate() {
        value += (byte as u32 & 0x7F) * multiplier;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 {
            return None;
        }
    }
    None
}

pub fn write_remaining_length(len: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = len;
    loop {
        let mut byte = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

/// Parsed MQTT packet.
#[derive(Debug, Clone)]
pub struct MqttPacket<'a> {
    buf: &'a [u8],
    header_len: usize,
    remaining_len: u32,
}

impl<'a> MqttPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.is_empty() {
            return None;
        }
        let (remaining_len, header_len) = read_remaining_length(&buf[1..])?;
        Some(Self {
            buf,
            header_len: 1 + header_len,
            remaining_len,
        })
    }

    pub fn packet_type(&self) -> MqttPacketType {
        MqttPacketType::from(self.buf[0])
    }
    pub fn flags(&self) -> u8 {
        self.buf[0] & 0x0F
    }
    pub fn qos(&self) -> QoS {
        QoS::from(self.flags())
    }
    pub fn remaining_length(&self) -> u32 {
        self.remaining_len
    }
    pub fn variable_header(&self) -> &'a [u8] {
        &self.buf[self.header_len..]
    }
    pub fn payload(&self) -> &'a [u8] {
        let vh = self.variable_header();
        let vh_len = self._vh_len().min(vh.len());
        &vh[vh_len..]
    }

    fn _vh_len(&self) -> usize {
        match self.packet_type() {
            MqttPacketType::Connect => {
                let vh = self.variable_header();
                if vh.len() < 6 {
                    return 0;
                }
                let protocol_name_len = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let mut pos = 2 + protocol_name_len;
                if pos + 4 > vh.len() {
                    return pos;
                }
                let protocol_level = vh[pos];
                let flags = vh[pos + 1];
                pos += 4; // protocol level, connect flags, keep_alive
                if protocol_level == 5 {
                    pos = skip_remaining_length(vh, pos);
                }
                pos = skip_length_prefixed(vh, pos); // client_id
                if flags & 0x04 != 0 && pos + 2 <= vh.len() {
                    if protocol_level == 5 {
                        pos = skip_remaining_length(vh, pos); // will properties
                    }
                    pos = skip_length_prefixed(vh, pos); // will topic
                    pos = skip_length_prefixed(vh, pos); // will message
                }
                if flags & 0x80 != 0 {
                    pos = skip_length_prefixed(vh, pos); // username
                }
                if flags & 0x40 != 0 {
                    pos = skip_length_prefixed(vh, pos); // password
                }
                pos
            }
            MqttPacketType::Connack => {
                let vh = self.variable_header();
                if vh.is_empty() {
                    return 0;
                }
                let mut pos = 2; // session_present + return_code
                if vh.len() > 2 {
                    // MQTT 5.0 properties
                    if let Some((_, plen)) = read_remaining_length(&vh[pos..]) {
                        pos += plen;
                    }
                }
                pos
            }
            MqttPacketType::Publish => {
                let vh = self.variable_header();
                if vh.len() < 2 {
                    return 0;
                }
                let tlen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let mut pos = 2 + tlen;
                if self.qos() as u8 > 0 {
                    pos += 2;
                } // packet_id
                pos
            }
            MqttPacketType::Subscribe => {
                let vh = self.variable_header();
                if vh.len() < 2 {
                    return 0;
                }
                2 // packet_id only
            }
            _ => 0,
        }
    }

    pub fn message(&self) -> MqttMessage<'a> {
        let vh = self.variable_header();
        match self.packet_type() {
            MqttPacketType::Connect => {
                if vh.len() < 6 {
                    return MqttMessage::Unknown {
                        packet_type: MqttPacketType::Connect,
                        data: vh,
                    };
                }
                let plen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let Some(fields) = vh.get(2 + plen..2 + plen + 4) else {
                    return MqttMessage::Unknown {
                        packet_type: MqttPacketType::Connect,
                        data: vh,
                    };
                };
                let proto = str::from_utf8(&vh[2..2 + plen]).unwrap_or("");
                let level = fields[0];
                let flags = fields[1];
                let keep_alive = u16::from_be_bytes([fields[2], fields[3]]);
                let mut pos = 6 + plen;
                // MQTT 5 properties
                let properties = if level == 5 {
                    parse_properties(&vh[pos..]).unwrap_or_default()
                } else {
                    vec![]
                };
                if level == 5 {
                    pos = skip_remaining_length(vh, pos);
                }
                let client_id = read_length_prefixed(vh, &mut pos)
                    .and_then(|bytes| str::from_utf8(bytes).ok())
                    .unwrap_or("");
                // will
                let (will_topic, will_message) = if flags & 0x04 != 0 {
                    if level == 5 {
                        pos = skip_remaining_length(vh, pos);
                    }
                    let will_topic =
                        read_length_prefixed(vh, &mut pos).and_then(|b| str::from_utf8(b).ok());
                    let will_message = read_length_prefixed(vh, &mut pos);
                    (will_topic, will_message)
                } else {
                    (None, None)
                };
                // username/password
                let username = if flags & 0x80 != 0 {
                    read_length_prefixed(vh, &mut pos).and_then(|b| str::from_utf8(b).ok())
                } else {
                    None
                };
                let password = if flags & 0x40 != 0 {
                    read_length_prefixed(vh, &mut pos)
                } else {
                    None
                };
                MqttMessage::Connect {
                    protocol_name: proto,
                    protocol_level: level,
                    clean_start: flags & 0x02 != 0,
                    keep_alive,
                    client_id,
                    will_topic,
                    will_message,
                    username,
                    password,
                    properties,
                }
            }
            MqttPacketType::Publish => {
                if vh.len() < 2 {
                    return MqttMessage::Unknown {
                        packet_type: MqttPacketType::Publish,
                        data: vh,
                    };
                }
                let tlen = u16::from_be_bytes([vh[0], vh[1]]) as usize;
                let Some(topic_bytes) = vh.get(2..2 + tlen) else {
                    return MqttMessage::Unknown {
                        packet_type: MqttPacketType::Publish,
                        data: vh,
                    };
                };
                let topic = str::from_utf8(topic_bytes).unwrap_or("");
                let mut pos = 2 + tlen;
                let packet_id = if self.qos() as u8 > 0 {
                    match vh.get(pos..pos + 2) {
                        Some(bytes) => {
                            pos += 2;
                            Some(u16::from_be_bytes([bytes[0], bytes[1]]))
                        }
                        None => None,
                    }
                } else {
                    None
                };
                let payload = &vh[pos..];
                MqttMessage::Publish {
                    topic,
                    packet_id,
                    payload,
                }
            }
            MqttPacketType::Subscribe => {
                let packet_id = if vh.len() >= 2 {
                    u16::from_be_bytes([vh[0], vh[1]])
                } else {
                    0
                };
                let topics = if vh.len() > 2 {
                    let data = &vh[2..];
                    let mut topics = Vec::new();
                    let mut p = 0;
                    while p + 3 <= data.len() {
                        let tl = u16::from_be_bytes([data[p], data[p + 1]]) as usize;
                        p += 2;
                        if p + tl < data.len() {
                            let tf = str::from_utf8(&data[p..p + tl]).unwrap_or("");
                            topics.push((tf, data[p + tl]));
                            p += tl + 1;
                        } else {
                            break;
                        }
                    }
                    topics
                } else {
                    vec![]
                };
                MqttMessage::Subscribe { packet_id, topics }
            }
            _ => MqttMessage::Unknown {
                packet_type: self.packet_type(),
                data: vh,
            },
        }
    }
}

/// Read a 2-byte length-prefixed field at `*pos`, advancing past it.
fn read_length_prefixed<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let prefix = buf.get(*pos..*pos + 2)?;
    let len = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
    let end = (*pos + 2).checked_add(len)?;
    let bytes = buf.get(*pos + 2..end)?;
    *pos = end;
    Some(bytes)
}

/// Skip a 2-byte length-prefixed field at `pos`.
///
/// Returns `pos` unchanged when the length prefix itself is missing.
fn skip_length_prefixed(buf: &[u8], pos: usize) -> usize {
    match buf.get(pos..pos + 2) {
        Some(prefix) => pos + 2 + u16::from_be_bytes([prefix[0], prefix[1]]) as usize,
        None => pos,
    }
}

/// Skip an MQTT variable-length integer at `pos`.
fn skip_remaining_length(buf: &[u8], pos: usize) -> usize {
    match buf.get(pos..).and_then(read_remaining_length) {
        Some((_, len)) => pos + len,
        None => pos,
    }
}

fn parse_properties(data: &[u8]) -> Option<Vec<MqttProperty>> {
    let (prop_len, mut pos) = read_remaining_length(data)?;
    let end = (pos + prop_len as usize).min(data.len());
    let mut props = Vec::new();
    while pos < end {
        let id = data[pos];
        pos += 1;
        match id {
            0x11 => {
                if pos + 4 <= end {
                    props.push(MqttProperty::SessionExpiryInterval(u32::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ])));
                    pos += 4;
                }
            }
            0x27 => {
                if pos + 4 <= end {
                    props.push(MqttProperty::MaximumPacketSize(u32::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ])));
                    pos += 4;
                }
            }
            0x23 => {
                if pos + 2 <= end {
                    props.push(MqttProperty::TopicAlias(u16::from_be_bytes([
                        data[pos],
                        data[pos + 1],
                    ])));
                    pos += 2;
                }
            }
            0x19 => {
                props.push(MqttProperty::RequestResponseInfo(
                    data.get(pos).copied().unwrap_or(0) != 0,
                ));
                pos += 1;
            }
            _ => {
                let mut v = vec![id];
                while pos < end {
                    v.push(data[pos]);
                    pos += 1;
                }
                props.push(MqttProperty::Unknown(id, v));
            }
        }
    }
    Some(props)
}

/// Parsed MQTT message (typed).
#[derive(Debug, Clone)]
pub enum MqttMessage<'a> {
    Connect {
        protocol_name: &'a str,
        protocol_level: u8,
        clean_start: bool,
        keep_alive: u16,
        client_id: &'a str,
        will_topic: Option<&'a str>,
        will_message: Option<&'a [u8]>,
        username: Option<&'a str>,
        password: Option<&'a [u8]>,
        properties: Vec<MqttProperty>,
    },
    Publish {
        topic: &'a str,
        packet_id: Option<u16>,
        payload: &'a [u8],
    },
    Subscribe {
        packet_id: u16,
        topics: Vec<(&'a str, u8)>,
    },
    Unknown {
        packet_type: MqttPacketType,
        data: &'a [u8],
    },
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
            MqttMessage::Connect {
                client_id,
                clean_start,
                keep_alive,
                ..
            } => {
                assert_eq!(client_id, "test");
                assert!(clean_start);
                assert_eq!(keep_alive, 60);
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn parse_mqtt_connect_with_will_and_credentials() {
        // flags: clean_start | will | username | password
        let mut vh = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 4, 0xC6];
        vh.extend_from_slice(&60u16.to_be_bytes());
        vh.extend_from_slice(&[0x00, 0x03, b'c', b'i', b'd']); // client_id
        vh.extend_from_slice(&[0x00, 0x02, b'w', b't']); // will topic
        vh.extend_from_slice(&[0x00, 0x02, b'w', b'm']); // will message
        vh.extend_from_slice(&[0x00, 0x01, b'u']); // username
        vh.extend_from_slice(&[0x00, 0x01, b'p']); // password

        let mut data = vec![0x10];
        data.extend_from_slice(&write_remaining_length(vh.len() as u32));
        data.extend_from_slice(&vh);

        let pkt = MqttPacket::parse(&data).unwrap();
        match pkt.message() {
            MqttMessage::Connect {
                client_id,
                will_topic,
                will_message,
                username,
                password,
                ..
            } => {
                assert_eq!(client_id, "cid");
                assert_eq!(will_topic, Some("wt"));
                assert_eq!(will_message, Some(&b"wm"[..]));
                assert_eq!(username, Some("u"));
                assert_eq!(password, Some(&b"p"[..]));
            }
            _ => panic!("expected Connect"),
        }
        assert!(pkt.payload().is_empty());
    }

    #[test]
    fn truncated_connect_does_not_panic() {
        // Protocol name length claims 16 bytes, but only 6 remain.
        let data = [0x10, 0x06, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];
        let pkt = MqttPacket::parse(&data).unwrap();
        assert!(matches!(pkt.message(), MqttMessage::Unknown { .. }));
        assert!(pkt.payload().is_empty());
    }

    #[test]
    fn truncated_publish_does_not_panic() {
        // Topic length claims 16 bytes, but the variable header is 2 bytes.
        let data = [0x30, 0x02, 0x00, 0x10];
        let pkt = MqttPacket::parse(&data).unwrap();
        assert!(matches!(pkt.message(), MqttMessage::Unknown { .. }));
        assert!(pkt.payload().is_empty());
    }

    #[test]
    fn parse_mqtt_subscribe() {
        let data = crate::mqtt::builder::MqttPacketBuilder::subscribe(7, &[("a/b", 1), ("c", 0)]);
        let pkt = MqttPacket::parse(&data).unwrap();
        match pkt.message() {
            MqttMessage::Subscribe { packet_id, topics } => {
                assert_eq!(packet_id, 7);
                assert_eq!(topics, vec![("a/b", 1), ("c", 0)]);
            }
            _ => panic!("expected Subscribe"),
        }
    }

    #[test]
    fn parse_mqtt_connack_is_unknown_message_with_empty_payload() {
        // CONNACK: session_present=0, return_code=0.
        let data = [0x20, 0x02, 0x00, 0x00];
        let pkt = MqttPacket::parse(&data).unwrap();
        assert!(matches!(pkt.message(), MqttMessage::Unknown { .. }));
        assert!(pkt.payload().is_empty());
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
            MqttMessage::Publish {
                topic: t,
                payload: p,
                ..
            } => {
                assert_eq!(t, "test/topic");
                assert_eq!(p, b"hello");
            }
            _ => panic!("expected Publish"),
        }
    }
}
