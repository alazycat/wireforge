//! MQTT type definitions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect, Connack, Publish, Puback, Pubrec, Pubrel,
    Pubcomp, Subscribe, Suback, Unsubscribe, Unsuback,
    Pingreq, Pingresp, Disconnect, Auth, Unknown(u8),
}

impl From<u8> for MqttPacketType {
    fn from(v: u8) -> Self {
        match v >> 4 {
            1 => Self::Connect, 2 => Self::Connack, 3 => Self::Publish,
            4 => Self::Puback, 5 => Self::Pubrec, 6 => Self::Pubrel,
            7 => Self::Pubcomp, 8 => Self::Subscribe, 9 => Self::Suback,
            10 => Self::Unsubscribe, 11 => Self::Unsuback,
            12 => Self::Pingreq, 13 => Self::Pingresp,
            14 => Self::Disconnect, 15 => Self::Auth,
            _ => Self::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoS { AtMostOnce, AtLeastOnce, ExactlyOnce }

impl From<u8> for QoS {
    fn from(v: u8) -> Self {
        match v & 0x06 >> 1 {
            0 => Self::AtMostOnce, 1 => Self::AtLeastOnce, 2 => Self::ExactlyOnce, _ => Self::AtMostOnce,
        }
    }
}

/// MQTT 5.0 property.
#[derive(Debug, Clone)]
pub enum MqttProperty {
    SessionExpiryInterval(u32),
    MaximumPacketSize(u32),
    TopicAlias(u16),
    RequestResponseInfo(bool),
    Unknown(u8, Vec<u8>),
}
