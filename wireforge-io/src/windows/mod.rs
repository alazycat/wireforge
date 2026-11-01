//! Windows platform implementation — NPcap L2 (via feature "npcap") and raw socket L3.

mod l3;
mod npcap;

pub use l3::{WinL3Receiver, WinL3Sender};
pub use npcap::{NpcapReader, NpcapWriter};
