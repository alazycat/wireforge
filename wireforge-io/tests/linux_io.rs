//! Privileged Linux I/O integration tests.
//!
//! These tests open AF_PACKET / raw sockets and therefore require root or
//! `CAP_NET_RAW`. They are ignored by default:
//!
//! ```sh
//! sudo -E cargo test -p wireforge-io --test linux_io -- --ignored
//! ```

#![cfg(target_os = "linux")]

use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::Duration;

use wireforge_core::icmp::Icmpv6PacketBuilder;
use wireforge_core::ipv6::Ipv6PacketBuilder;
use wireforge_core::types::IpProtocol;
use wireforge_io::linux::{L2Receiver, L3Receiver, L3ReceiverV6, L3SenderV6};
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

#[test]
#[ignore = "requires root/CAP_NET_RAW to open an ICMPv6 raw socket"]
fn l3_v6_opens_icmpv6_socket_and_times_out() {
    let mut rx = L3ReceiverV6::new(IpProtocol::Icmpv6).expect("open ICMPv6 raw socket");
    rx.set_timeout(Some(Duration::from_millis(50)))
        .expect("set SO_RCVTIMEO");

    match rx.recv() {
        Ok(_packet) => {}
        Err(IoError::Timeout) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
#[ignore = "requires root/CAP_NET_RAW to open raw sockets"]
fn l3_v6_send_and_receive_echo_request() {
    let src = Ipv6Addr::LOCALHOST;
    let dst = Ipv6Addr::LOCALHOST;

    let mut rx = L3ReceiverV6::new(IpProtocol::Icmpv6).expect("open ICMPv6 raw socket");
    rx.set_timeout(Some(Duration::from_millis(500)))
        .expect("set SO_RCVTIMEO");

    let icmp = Icmpv6PacketBuilder::echo_request()
        .identifier(0x1234)
        .sequence_number(1)
        .body(b"wireforge-v6")
        .build(src, dst);
    let ipv6 = Ipv6PacketBuilder::new()
        .source(src)
        .destination(dst)
        .next_header(IpProtocol::Icmpv6)
        .hop_limit(64)
        .payload(&icmp)
        .expect("payload should fit")
        .build();

    let tx = L3SenderV6::new().expect("open IPv6 raw sender");
    tx.send_to(&ipv6, SocketAddrV6::new(dst, 0, 0, 0))
        .expect("send IPv6 packet");

    let mut received = false;
    for _ in 0..8 {
        match rx.recv() {
            Ok(packet) => {
                if packet.source() == src && packet.destination() == dst {
                    received = true;
                    break;
                }
            }
            Err(IoError::Timeout) => break,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(received, "did not receive the sent IPv6 packet");
}
