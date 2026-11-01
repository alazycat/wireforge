//! Modbus TCP packet parser.

use super::types::ModbusFunction;
use wireforge_core::util::read_u16be;

const MBAP_HEADER_LEN: usize = 7;

/// Zero-copy Modbus TCP packet parser.
#[derive(Debug, Clone)]
pub struct ModbusTcpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> ModbusTcpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MBAP_HEADER_LEN {
            return None;
        }
        Some(Self { buf })
    }

    pub fn transaction_id(&self) -> u16 {
        read_u16be(&self.buf[0..2])
    }
    pub fn protocol_id(&self) -> u16 {
        read_u16be(&self.buf[2..4])
    }
    pub fn length(&self) -> u16 {
        read_u16be(&self.buf[4..6])
    }
    pub fn unit_id(&self) -> u8 {
        self.buf[6]
    }
    pub fn function_code(&self) -> u8 {
        self.buf.get(7).copied().unwrap_or(0)
    }
    pub fn pdu_data(&self) -> &'a [u8] {
        &self.buf[MBAP_HEADER_LEN..]
    }

    pub fn function(&self) -> ModbusFunction<'a> {
        let pdu = self.pdu_data();
        if pdu.is_empty() {
            return ModbusFunction::Unknown {
                function_code: 0,
                data: &[],
            };
        }
        let fc = pdu[0];
        let data = &pdu[1..];
        match fc {
            1 => ModbusFunction::ReadCoils {
                starting_address: read_u16_at(data, 0),
                quantity: read_u16_at(data, 2),
            },
            2 => ModbusFunction::ReadDiscreteInputs {
                starting_address: read_u16_at(data, 0),
                quantity: read_u16_at(data, 2),
            },
            3 => ModbusFunction::ReadHoldingRegisters {
                starting_address: read_u16_at(data, 0),
                quantity: read_u16_at(data, 2),
            },
            4 => ModbusFunction::ReadInputRegisters {
                starting_address: read_u16_at(data, 0),
                quantity: read_u16_at(data, 2),
            },
            5 => ModbusFunction::WriteSingleCoil {
                output_address: read_u16_at(data, 0),
                value: data.len() >= 3 && data[2] == 0xFF,
            },
            6 => ModbusFunction::WriteSingleRegister {
                register_address: read_u16_at(data, 0),
                value: read_u16_at(data, 2),
            },
            15 => ModbusFunction::WriteMultipleCoils {
                starting_address: read_u16_at(data, 0),
                quantity: read_u16_at(data, 2),
                byte_count: data.get(4).copied().unwrap_or(0),
                values: data.get(5..).unwrap_or(&[]),
            },
            16 => ModbusFunction::WriteMultipleRegisters {
                starting_address: read_u16_at(data, 0),
                quantity: read_u16_at(data, 2),
                byte_count: data.get(4).copied().unwrap_or(0),
                values: data.get(5..).unwrap_or(&[]),
            },
            _ => ModbusFunction::Unknown {
                function_code: fc,
                data,
            },
        }
    }
}

/// Read a big-endian u16 at `offset`, returning 0 when the field is truncated.
fn read_u16_at(data: &[u8], offset: usize) -> u16 {
    data.get(offset..offset + 2).map(read_u16be).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_read_coils() {
        let data = &[
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0A,
        ];
        // transaction=1, proto=0, len=6, unit=1, fc=1(read coils), addr=0, qty=10
        let pkt = ModbusTcpPacket::new(data).unwrap();
        assert_eq!(pkt.transaction_id(), 1);
        assert_eq!(pkt.function_code(), 1);
        match pkt.function() {
            ModbusFunction::ReadCoils {
                starting_address,
                quantity,
            } => {
                assert_eq!(starting_address, 0);
                assert_eq!(quantity, 10);
            }
            _ => panic!("expected ReadCoils"),
        }
    }

    #[test]
    fn parse_read_holding_registers_response() {
        // Function 3 response: 3 registers [0x0001, 0x0002, 0x0003]
        let data = &[
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01, 0x03, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00,
            0x03,
        ];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        assert_eq!(pkt.function_code(), 3);
    }

    #[test]
    fn parse_write_single_register() {
        let data = &[
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x2A,
        ];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::WriteSingleRegister {
                register_address,
                value,
            } => {
                assert_eq!(register_address, 1);
                assert_eq!(value, 42);
            }
            _ => panic!("expected WriteSingleRegister"),
        }
    }

    #[test]
    fn parse_write_single_coil() {
        // fc=5, address=0x0010, value=0xFF00 (on)
        let data = &[
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x10, 0xFF, 0x00,
        ];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::WriteSingleCoil {
                output_address,
                value,
            } => {
                assert_eq!(output_address, 0x0010);
                assert!(value);
            }
            _ => panic!("expected WriteSingleCoil"),
        }
    }

    #[test]
    fn parse_write_multiple_coils() {
        // fc=15, address=1, quantity=3, byte_count=1, values=[0b101]
        let data = &[
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x0F, 0x00, 0x01, 0x00, 0x03, 0x01, 0x05,
        ];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::WriteMultipleCoils {
                starting_address,
                quantity,
                byte_count,
                values,
            } => {
                assert_eq!(starting_address, 1);
                assert_eq!(quantity, 3);
                assert_eq!(byte_count, 1);
                assert_eq!(values, &[0x05]);
            }
            _ => panic!("expected WriteMultipleCoils"),
        }
    }

    #[test]
    fn parse_write_multiple_registers() {
        // fc=16, address=0, quantity=1, byte_count=2, value=0x002A
        let data = &[
            0x00u8, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
            0x2A,
        ];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::WriteMultipleRegisters {
                starting_address,
                quantity,
                byte_count,
                values,
            } => {
                assert_eq!(starting_address, 0);
                assert_eq!(quantity, 1);
                assert_eq!(byte_count, 2);
                assert_eq!(values, &[0x00, 0x2A]);
            }
            _ => panic!("expected WriteMultipleRegisters"),
        }
    }

    #[test]
    fn truncated_pdu_reads_zero_fields() {
        // fc=1 with no address/quantity bytes.
        let data = &[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::ReadCoils {
                starting_address,
                quantity,
            } => {
                assert_eq!(starting_address, 0);
                assert_eq!(quantity, 0);
            }
            _ => panic!("expected ReadCoils"),
        }
    }

    #[test]
    fn truncated_write_multiple_pdu_does_not_panic() {
        // fc=15 with none of the address/quantity/byte-count bytes present.
        let data = &[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x0F];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::WriteMultipleCoils {
                starting_address,
                quantity,
                byte_count,
                values,
            } => {
                assert_eq!(starting_address, 0);
                assert_eq!(quantity, 0);
                assert_eq!(byte_count, 0);
                assert!(values.is_empty());
            }
            _ => panic!("expected WriteMultipleCoils"),
        }
    }

    #[test]
    fn parse_too_short() {
        assert!(ModbusTcpPacket::new(&[]).is_none());
        assert!(ModbusTcpPacket::new(&[0u8; 6]).is_none());
        assert!(ModbusTcpPacket::new(&[0u8; 7]).is_some());
    }
}
