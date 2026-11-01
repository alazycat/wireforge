//! Cross-platform datalink configuration.
//!
//! Fields are hints: each backend applies the options it supports and ignores
//! the rest.
//!
//! Platform support:
//! - **Linux**: all fields except [`Config::bpf_fd_attempts`].
//! - **Windows**: [`Config::read_timeout`] and [`Config::promiscuous`]; buffer,
//!   write-timeout, fanout and socket-fd options are ignored by the Npcap
//!   backend.
//! - **macOS**: the BPF backend is currently a stub, so all options are
//!   ignored until #3/#4 land.

use std::time::Duration;

/// Packet fanout algorithm (Linux only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FanoutType {
    /// Hash packets by flow, keeping per-flow ordering.
    Hash,
    /// Round-robin load balancing.
    LoadBalance,
    /// Select the socket by the CPU that received the packet.
    Cpu,
    /// Process on one socket and roll over when it becomes backlogged.
    Rollover,
    /// Choose a socket at random.
    Random,
    /// Queue-based selection.
    Queue,
    /// Classic BPF-based selection.
    Cbpf,
    /// eBPF-based selection.
    Ebpf,
}

/// Packet fanout settings (Linux only).
///
/// Applied with `setsockopt(SOL_PACKET, PACKET_FANOUT)`. All sockets joining
/// the same group must use the same protocol, device, mode and flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FanoutOption {
    /// Fanout group ID (the kernel supports up to 65536 groups per namespace).
    pub group_id: u16,
    /// Packet distribution algorithm.
    pub fanout_type: FanoutType,
    /// Request defragmentation of incoming packets
    /// (`PACKET_FANOUT_FLAG_DEFRAG`).
    pub defrag: bool,
    /// Enable rollover when a socket becomes backlogged
    /// (`PACKET_FANOUT_FLAG_ROLLOVER`).
    pub rollover: bool,
}

/// Configuration for opening a datalink reader/writer pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Receive buffer size.
    ///
    /// On Linux this sets both the userspace receive buffer and `SO_RCVBUF`.
    /// Frames larger than this are truncated by `recv(2)`.
    /// Defaults to 64 KiB.
    pub read_buffer_size: usize,

    /// Send buffer size (`SO_SNDBUF` on Linux). Defaults to 64 KiB.
    pub write_buffer_size: usize,

    /// Receive timeout. On Linux this is `SO_RCVTIMEO`; on Windows it is the
    /// Npcap read timeout. Defaults to blocking.
    pub read_timeout: Option<Duration>,

    /// Send timeout (`SO_SNDTIMEO` on Linux). Unsupported on Windows.
    /// Defaults to blocking.
    pub write_timeout: Option<Duration>,

    /// Open the reader in promiscuous mode. Defaults to `false`.
    pub promiscuous: bool,

    /// Reuse an existing `AF_PACKET` file descriptor for the reader
    /// (Linux only).
    ///
    /// Ownership of the descriptor transfers to the reader and it is closed
    /// when the reader is dropped. Ignored by senders.
    pub socket_fd: Option<i32>,

    /// Number of `/dev/bpfN` devices to try before failing (macOS only).
    /// Defaults to 1000. Ignored until the BPF backend is implemented.
    pub bpf_fd_attempts: usize,

    /// Packet fanout settings for the reader (Linux only).
    pub linux_fanout: Option<FanoutOption>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            read_buffer_size: 65536,
            write_buffer_size: 65536,
            read_timeout: None,
            write_timeout: None,
            promiscuous: false,
            socket_fd: None,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
        }
    }
}
