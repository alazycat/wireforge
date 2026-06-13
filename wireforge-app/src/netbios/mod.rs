//! NetBIOS Name Service parser (RFC 1001/1002).
mod types; mod parser;
pub use types::NetbiosNameType;
pub use parser::NetbiosNsPacket;
