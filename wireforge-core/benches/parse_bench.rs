use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wireforge_core::arp::ArpPacket;
use wireforge_core::ether::EthernetPacket;
use wireforge_core::icmp::{IcmpPacket, Icmpv6Packet};
use wireforge_core::ipv4::Ipv4Packet;
use wireforge_core::ipv6::Ipv6Packet;
use wireforge_core::tcp::TcpPacket;
use wireforge_core::udp::UdpPacket;
use wireforge_core::vlan::VlanPacket;

fn bench_parse_ethernet(c: &mut Criterion) {
    let frame = [
        0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
    ];
    c.bench_function("parse/ethernet", |b| {
        b.iter(|| EthernetPacket::new(black_box(&frame)))
    });
}

fn bench_parse_ipv4(c: &mut Criterion) {
    let pkt = [0x45u8, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
        0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02];
    c.bench_function("parse/ipv4", |b| {
        b.iter(|| Ipv4Packet::new(black_box(&pkt)))
    });
}

fn bench_parse_ipv6(c: &mut Criterion) {
    let pkt = [0x60u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40]; // 40 bytes
    let mut buf = [0u8; 40];
    buf[..8].copy_from_slice(&pkt);
    c.bench_function("parse/ipv6", |b| {
        b.iter(|| Ipv6Packet::new(black_box(&buf)))
    });
}

fn bench_parse_arp(c: &mut Criterion) {
    let mut pkt = [0u8; 28];
    pkt[..2].copy_from_slice(&[0x00, 0x01]);
    pkt[2..4].copy_from_slice(&[0x08, 0x00]);
    pkt[4] = 6; pkt[5] = 4;
    pkt[6..8].copy_from_slice(&[0x00, 0x01]);
    c.bench_function("parse/arp", |b| {
        b.iter(|| ArpPacket::new(black_box(&pkt)))
    });
}

fn bench_parse_tcp(c: &mut Criterion) {
    let mut pkt = [0u8; 20];
    pkt[12] = 0x50;
    c.bench_function("parse/tcp", |b| {
        b.iter(|| TcpPacket::new(black_box(&pkt)))
    });
}

fn bench_parse_udp(c: &mut Criterion) {
    let pkt = [0u8; 8];
    c.bench_function("parse/udp", |b| {
        b.iter(|| UdpPacket::new(black_box(&pkt)))
    });
}

criterion_group!(benches,
    bench_parse_ethernet,
    bench_parse_ipv4,
    bench_parse_ipv6,
    bench_parse_arp,
    bench_parse_tcp,
    bench_parse_udp,
);
criterion_main!(benches);
