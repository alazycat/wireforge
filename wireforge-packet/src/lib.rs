//! WireForge Packet — unified packet enum and protocol dispatch.
//!
//! This crate provides a single `Packet` enum that can represent any
//! supported protocol layer, plus helper functions to automatically
//! dispatch from raw bytes to the correct protocol parser.

// Will be implemented after wireforge-core protocols are ready:
// pub enum Packet<'a> { ... }
// pub fn parse_ethernet_frame(buf: &[u8]) -> ...;
