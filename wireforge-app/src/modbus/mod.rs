//! Modbus TCP protocol parser (MBAP header + PDU function code dispatch).

mod types;
mod parser;

pub use types::ModbusFunction;
pub use parser::ModbusTcpPacket;
