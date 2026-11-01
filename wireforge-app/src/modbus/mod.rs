//! Modbus TCP protocol parser (MBAP header + PDU function code dispatch).

mod parser;
mod types;

pub use parser::ModbusTcpPacket;
pub use types::ModbusFunction;
