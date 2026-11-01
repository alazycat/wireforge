//! NetBIOS Name Service parser (RFC 1001/1002).

mod parser;
mod types;

pub use parser::NetbiosNsPacket;
pub use types::NetbiosNameType;
