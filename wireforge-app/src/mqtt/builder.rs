//! MQTT packet builder.

use super::parser::write_remaining_length;

pub struct MqttPacketBuilder;

impl MqttPacketBuilder {
    pub fn connect(client_id: &str) -> Vec<u8> {
        let mut body = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 4u8, 0x02u8];
        body.extend_from_slice(&60u16.to_be_bytes());
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id.as_bytes());
        frame(0x10, &body)
    }

    pub fn publish(topic: &str, payload: &[u8], qos: u8, retain: bool) -> Vec<u8> {
        let mut body = Vec::with_capacity(2 + topic.len() + payload.len());
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(payload);

        let mut type_byte = 0x30; // Publish
        type_byte |= (qos & 0x03) << 1;
        if retain {
            type_byte |= 0x01;
        }
        frame(type_byte, &body)
    }

    pub fn subscribe(packet_id: u16, topics: &[(&str, u8)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&packet_id.to_be_bytes());
        for (topic, qos) in topics {
            body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
            body.extend_from_slice(topic.as_bytes());
            body.push(*qos & 0x03);
        }
        frame(0x82, &body)
    }
}

/// Prefix a packet body with its fixed header byte and remaining length.
fn frame(first_byte: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 4 + body.len());
    packet.push(first_byte);
    packet.extend_from_slice(&write_remaining_length(body.len() as u32));
    packet.extend_from_slice(body);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::parser::MqttPacket;
    use crate::mqtt::types::MqttPacketType;

    #[test]
    fn build_connect_roundtrip() {
        let pkt = MqttPacketBuilder::connect("sensor1");
        let parsed = MqttPacket::parse(&pkt).unwrap();
        assert_eq!(parsed.packet_type(), MqttPacketType::Connect);
    }
}
