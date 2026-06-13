//! WireForge IO — cross-platform raw socket I/O for packet capture and injection.
//!
//! # Platform Support
//!
//! | Platform | L2 Capture | L3 Capture | Backend |
//! |----------|------------|------------|---------|
//! | Linux    | AF_PACKET  | raw socket | socket2 + libc |
//! | macOS    | BPF        | raw socket | /dev/bpf + libc |
//! | Windows  | NPcap      | raw socket | npcap crate |
//!
//! # Quick Start
//!
//! ```rust,no_run
//! # use wireforge_io::{DefaultL2Reader, traits::L2Reader};
//! # fn main() -> Result<(), wireforge_io::IoError> {
//! let mut rx = DefaultL2Reader::new("eth0")?;
//! let eth = rx.recv()?;
//! println!("EtherType: {:?}", eth.ethertype());
//! # Ok(())
//! # }
//! ```
//!
//! # Permissions
//!
//! L2 capture requires root (Linux/macOS) or Administrator (Windows).
//! `list_interfaces()` does not require elevated privileges.

mod error;
pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

mod interface;

pub use error::IoError;
pub use interface::{list_interfaces, Interface};

// Re-export existing concrete types from their new platform homes
#[cfg(target_os = "linux")]
pub use linux::{L2Receiver, L2Sender, L3Receiver, L3Sender};

// Platform-adaptive type aliases
#[cfg(target_os = "linux")]
pub type DefaultL2Reader = linux::L2Receiver;
#[cfg(target_os = "macos")]
pub type DefaultL2Reader = macos::BpfReader;
#[cfg(target_os = "windows")]
pub type DefaultL2Reader = windows::NpcapReader;

#[cfg(target_os = "linux")]
pub type DefaultL2Writer = linux::L2Sender;
#[cfg(target_os = "macos")]
pub type DefaultL2Writer = macos::BpfWriter;
#[cfg(target_os = "windows")]
pub type DefaultL2Writer = windows::NpcapWriter;

#[cfg(target_os = "linux")]
pub type DefaultL3Reader = linux::L3Receiver;
#[cfg(target_os = "macos")]
pub type DefaultL3Reader = macos::BsdL3Receiver;
#[cfg(target_os = "windows")]
pub type DefaultL3Reader = windows::WinL3Receiver;

#[cfg(target_os = "linux")]
pub type DefaultL3Writer = linux::L3Sender;
#[cfg(target_os = "macos")]
pub type DefaultL3Writer = macos::BsdL3Sender;
#[cfg(target_os = "windows")]
pub type DefaultL3Writer = windows::WinL3Sender;
