//! macOS/BSD platform implementation — BPF L2 and raw socket L3 (IPv4/IPv6 stubs).

mod bpf;
mod l3;

use crate::config::Config;
use crate::error::IoError;

pub use bpf::{BpfReader, BpfWriter};
pub use l3::{BsdL3Receiver, BsdL3ReceiverV6, BsdL3Sender, BsdL3SenderV6};

/// Open a configured BPF reader/writer pair.
///
/// Returns [`IoError::UnsupportedPlatform`] until the BPF backend is
/// implemented (#3/#4).
pub fn channel(ifname: &str, _config: Config) -> Result<(BpfReader, BpfWriter), IoError> {
    let reader = BpfReader::new(ifname)?;
    let writer = BpfWriter::new(ifname)?;
    Ok((reader, writer))
}
