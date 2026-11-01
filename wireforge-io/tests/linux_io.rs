//! Privileged Linux I/O integration tests.
//!
//! These tests open AF_PACKET / raw sockets and therefore require root or
//! `CAP_NET_RAW`. They are ignored by default:
//!
//! ```sh
//! sudo -E cargo test -p wireforge-io --test linux_io -- --ignored
//! ```

#![cfg(target_os = "linux")]

use std::time::Duration;

use wireforge_core::types::IpProtocol;
use wireforge_io::linux::{L2Receiver, L3Receiver};
use wireforge_io::IoError;

#[test]
#[ignore = "requires root/CAP_NET_RAW to open an AF_PACKET socket"]
fn l2_opens_loopback_and_times_out() {
    let mut rx = L2Receiver::new("lo").expect("open AF_PACKET socket on lo");
    rx.set_timeout(Some(Duration::from_millis(50)))
        .expect("set SO_RCVTIMEO");

    match rx.recv() {
        Ok(_frame) => {}
        Err(IoError::Timeout) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
#[ignore = "requires root/CAP_NET_RAW to open an ICMP raw socket"]
fn l3_opens_icmp_socket_and_times_out() {
    let mut rx = L3Receiver::new(IpProtocol::Icmp).expect("open ICMP raw socket");
    rx.set_timeout(Some(Duration::from_millis(50)))
        .expect("set SO_RCVTIMEO");

    match rx.recv() {
        Ok(_packet) => {}
        Err(IoError::Timeout) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}
