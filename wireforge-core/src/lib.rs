//! WireForge Core — zero-copy network packet parsing and construction.
//!
//! This crate provides:
//! - Protocol type definitions (EtherType, IpProtocol, etc.)
//! - Zero-copy packet parsers for L2-L4 protocols
//! - Builder-based packet constructors
//! - Checksum computation utilities
//!
//! # no_std
//!
//! This crate is `no_std` compatible (requires `alloc`).

#![no_std]

extern crate alloc;

pub mod types;
pub mod util;
pub mod ether;
pub mod vlan;
pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod icmp;
pub mod tcp;
pub mod udp;

pub use util::BuildError;
