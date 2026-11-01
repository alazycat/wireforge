//! Windows platform implementation — NPcap L2 (via feature "npcap") and raw socket L3 (IPv4/IPv6).

mod l3;
mod npcap;

pub use l3::{WinL3Receiver, WinL3ReceiverV6, WinL3Sender, WinL3SenderV6};
pub use npcap::{npcap_devices, NpcapDevice, NpcapReader, NpcapWriter};
