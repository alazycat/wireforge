//! macOS/BSD platform implementation — BPF L2 and raw socket L3 (IPv4/IPv6 stubs).

mod bpf;
mod l3;

use crate::config::Config;
use crate::error::IoError;

pub use bpf::{BpfReader, BpfWriter};
pub use l3::{BsdL3Receiver, BsdL3ReceiverV6, BsdL3Sender, BsdL3SenderV6};

/// Open a configured BPF reader/writer pair.
///
/// Both endpoints get their own `/dev/bpf` file descriptor bound to
/// `ifname`. Requires root; each open attempt honors
/// [`Config::bpf_fd_attempts`].
pub fn channel(ifname: &str, config: Config) -> Result<(BpfReader, BpfWriter), IoError> {
    let reader = BpfReader::with_config(ifname, config)?;
    let writer = BpfWriter::new(ifname)?;
    Ok((reader, writer))
}
