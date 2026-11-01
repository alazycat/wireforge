//! Linux platform implementation — AF_PACKET L2 and raw socket L3 (IPv4/IPv6).

mod l2;
mod l3;

use crate::config::Config;
use crate::error::IoError;

pub use l2::{L2Receiver, L2Sender};
pub use l3::{L3Receiver, L3ReceiverV6, L3Sender, L3SenderV6};

/// Open a configured AF_PACKET reader/writer pair on `ifname`.
///
/// Linux-specific options in [`Config`] (`socket_fd`, `linux_fanout`) apply to
/// the reader; the writer opens its own socket and ignores `socket_fd`.
pub fn channel(ifname: &str, config: Config) -> Result<(L2Receiver, L2Sender), IoError> {
    let reader = L2Receiver::with_config(ifname, config)?;
    let writer = L2Sender::with_config(ifname, config)?;
    Ok((reader, writer))
}
