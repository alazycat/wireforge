//! Modbus TCP packet parser.

use super::types::ModbusFunction;

const MBAP_HEADER_LEN: usize = 7;

/// Zero-copy Modbus TCP packet parser.
pub struct ModbusTcpPacket<'a> { buf: &'a [u8] }

impl<'a> ModbusTcpPacket<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < MBAP_HEADER_LEN { return None; }
        Some(Self { buf })
    }

    pub fn transaction_id(&self) -> u16 { u16::from_be_bytes([self.buf[0], self.buf[1]]) }
    pub fn protocol_id(&self) -> u16 { u16::from_be_bytes([self.buf[2], self.buf[3]]) }
    pub fn length(&self) -> u16 { u16::from_be_bytes([self.buf[4], self.buf[5]]) }
    pub fn unit_id(&self) -> u8 { self.buf[6] }
    pub fn function_code(&self) -> u8 { self.buf.get(7).copied().unwrap_or(0) }
    pub fn pdu_data(&self) -> &'a [u8] { &self.buf[MBAP_HEADER_LEN..] }

    pub fn function(&self) -> ModbusFunction<'a> {
        let pdu = self.pdu_data();
        if pdu.is_empty() { return ModbusFunction::Unknown { function_code: 0, data: &[] }; }
        let fc = pdu[0];
        let data = &pdu[1..];
        match fc {
            1 => ModbusFunction::ReadCoils {
                starting_address: self._u16(data, 0), quantity: self._u16(data, 2),
            },
            2 => ModbusFunction::ReadDiscreteInputs {
                starting_address: self._u16(data, 0), quantity: self._u16(data, 2),
            },
            3 => {
                if data.len() >= 4 && data.len() >= 5 + data[2] as usize {
                    // Response format checked by caller
                    ModbusFunction::ReadHoldingRegisters { starting_address: self._u16(data, 0), quantity: self._u16(data, 2) }
                } else {
                    ModbusFunction::ReadHoldingRegisters { starting_address: self._u16(data, 0), quantity: self._u16(data, 2) }
                }
            }
            4 => ModbusFunction::ReadInputRegisters {
                starting_address: self._u16(data, 0), quantity: self._u16(data, 2),
            },
            5 => ModbusFunction::WriteSingleCoil {
                output_address: self._u16(data, 0),
                value: data.len() >= 3 && data[2] == 0xFF,
            },
            6 => ModbusFunction::WriteSingleRegister {
                register_address: self._u16(data, 0), value: self._u16(data, 2),
            },
            15 => ModbusFunction::WriteMultipleCoils {
                starting_address: self._u16(data, 0), quantity: self._u16(data, 2),
                byte_count: *data.get(4).unwrap_or(&0), values: &data[5..],
            },
            16 => ModbusFunction::WriteMultipleRegisters {
                starting_address: self._u16(data, 0), quantity: self._u16(data, 2),
                byte_count: *data.get(4).unwrap_or(&0), values: &data[5..],
            },
            _ => ModbusFunction::Unknown { function_code: fc, data },
        }
    }

    fn _u16(&self, data: &[u8], off: usize) -> u16 {
        if off + 2 <= data.len() { u16::from_be_bytes([data[off], data[off+1]]) } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_read_coils() {
        let data = &[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0A];
        // transaction=1, proto=0, len=6, unit=1, fc=1(read coils), addr=0, qty=10
        let pkt = ModbusTcpPacket::new(data).unwrap();
        assert_eq!(pkt.transaction_id(), 1);
        assert_eq!(pkt.function_code(), 1);
        match pkt.function() {
            ModbusFunction::ReadCoils { starting_address, quantity } => {
                assert_eq!(starting_address, 0); assert_eq!(quantity, 10);
            }
            _ => panic!("expected ReadCoils"),
        }
    }

    #[test]
    fn parse_read_holding_registers_response() {
        // Function 3 response: 3 registers [0x0001, 0x0002, 0x0003]
        let data = &[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01, 0x03, 0x06,
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        assert_eq!(pkt.function_code(), 3);
    }

    #[test]
    fn parse_write_single_register() {
        let data = &[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x2A];
        let pkt = ModbusTcpPacket::new(data).unwrap();
        match pkt.function() {
            ModbusFunction::WriteSingleRegister { register_address, value } => {
                assert_eq!(register_address, 1); assert_eq!(value, 42);
            }
            _ => panic!("expected WriteSingleRegister"),
        }
    }

    #[test]
    fn parse_too_short() {
        assert!(ModbusTcpPacket::new(&[]).is_none());
        assert!(ModbusTcpPacket::new(&[0u8; 6]).is_none());
        assert!(ModbusTcpPacket::new(&[0u8; 7]).is_some());
    }
}
