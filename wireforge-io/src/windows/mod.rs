//! Windows platform implementation — NPcap L2 (via feature "npcap") and raw socket L3.

mod npcap;
mod l3;

pub use npcap::{NpcapReader, NpcapWriter};
pub use l3::{WinL3Receiver, WinL3Sender};
