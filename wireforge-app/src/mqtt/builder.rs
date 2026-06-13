//! MQTT packet builder.

use super::parser::write_remaining_length;

pub struct MqttPacketBuilder;

impl MqttPacketBuilder {
    pub fn connect(client_id: &str) -> Vec<u8> {
        let mut payload = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 4u8, 0x02u8];
        payload.extend_from_slice(&60u16.to_be_bytes());
        payload.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        payload.extend_from_slice(client_id.as_bytes());
        let mut pkt = vec![0x10u8]; // Connect
        pkt.extend_from_slice(&write_remaining_length(payload.len() as u32));
        pkt.extend_from_slice(&payload);
        pkt
    }

    pub fn publish(topic: &str, payload: &[u8], qos: u8, retain: bool) -> Vec<u8> {
        let mut vh = vec![];
        vh.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        vh.extend_from_slice(topic.as_bytes());
        let mut type_byte = 0x30; // Publish
        type_byte |= (qos & 0x03) << 1;
        if retain { type_byte |= 0x01; }
        let total = vh.len() + payload.len();
        let mut pkt = vec![type_byte];
        pkt.extend_from_slice(&write_remaining_length(total as u32));
        pkt.extend_from_slice(&vh);
        pkt.extend_from_slice(payload);
        pkt
    }

    pub fn subscribe(packet_id: u16, topics: &[(&str, u8)]) -> Vec<u8> {
        let mut payload = vec![];
        payload.extend_from_slice(&packet_id.to_be_bytes());
        for (topic, qos) in topics {
            payload.extend_from_slice(&(topic.len() as u16).to_be_bytes());
            payload.extend_from_slice(topic.as_bytes());
            payload.push(*qos & 0x03);
        }
        let mut pkt = vec![0x82u8]; // Subscribe
        pkt.extend_from_slice(&write_remaining_length(payload.len() as u32));
        pkt.extend_from_slice(&payload);
        pkt
    }
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
