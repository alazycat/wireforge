//! WireForge IO — Linux raw socket I/O for packet capture and injection.
//!
//! # Platform
//!
//! Linux only (requires AF_PACKET and SOCK_RAW support).

mod error;
#[cfg(target_os = "linux")]
mod l2;
#[cfg(target_os = "linux")]
mod l3;

pub use error::IoError;
#[cfg(target_os = "linux")]
pub use l2::{L2Receiver, L2Sender};
#[cfg(target_os = "linux")]
pub use l3::{L3Receiver, L3Sender};
