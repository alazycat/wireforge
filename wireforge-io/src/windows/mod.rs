//! Windows platform implementation — NPcap L2 (via feature "npcap") and raw socket L3 (IPv4/IPv6).

mod l3;
mod npcap;

use crate::config::Config;
use crate::error::IoError;

pub use l3::{WinL3Receiver, WinL3ReceiverV6, WinL3Sender, WinL3SenderV6};
pub use npcap::{npcap_devices, NpcapDevice, NpcapReader, NpcapWriter};

/// Open a configured Npcap reader/writer pair.
///
/// `read_timeout` and `promiscuous` are applied to the reader. Npcap does not
/// support write buffer/timeout options; Linux-only options are ignored.
pub fn channel(ifname: &str, config: Config) -> Result<(NpcapReader, NpcapWriter), IoError> {
    let reader = NpcapReader::with_options(ifname, config.promiscuous, config.read_timeout)?;
    let writer = NpcapWriter::new(ifname)?;
    Ok((reader, writer))
}

#[cfg(test)]
mod tests {
    use super::{channel, npcap_devices};
    use crate::config::Config;
    use crate::error::IoError;
    use std::time::Duration;

    #[test]
    #[ignore = "requires Npcap"]
    fn channel_opens_with_config() {
        let devices = npcap_devices().expect("Npcap devices");
        let Some(device) = devices.iter().find(|device| {
            device.name.contains("Loopback")
                || device
                    .description
                    .as_deref()
                    .is_some_and(|desc| desc.contains("Loopback"))
        }) else {
            return;
        };

        let config = Config {
            read_timeout: Some(Duration::from_millis(100)),
            ..Config::default()
        };
        let (mut rx, tx) = channel(&device.name, config).expect("open channel");

        tx.send(&[0u8; 60]).expect("send should succeed");
        match rx.recv() {
            Ok(_) | Err(IoError::Timeout) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
