use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::Ipv4Addr;
use wireforge_core::ether::EthernetPacketBuilder;
use wireforge_core::ipv4::Ipv4PacketBuilder;
use wireforge_core::tcp::TcpPacketBuilder;
use wireforge_core::types::IpProtocol;

fn bench_build_ipv4(c: &mut Criterion) {
    c.bench_function("build/ipv4", |b| {
        b.iter(|| {
            Ipv4PacketBuilder::new()
                .source(Ipv4Addr::new(10, 0, 0, 1))
                .destination(Ipv4Addr::new(10, 0, 0, 2))
                .protocol(IpProtocol::Tcp)
                .ttl(64)
                .build()
        })
    });
}

fn bench_build_ethernet(c: &mut Criterion) {
    c.bench_function("build/ethernet", |b| {
        b.iter(|| {
            EthernetPacketBuilder::new()
                .dst_mac([0xFF; 6])
                .src_mac([0x00; 6])
                .ethertype(wireforge_core::types::EtherType::Ipv4)
                .payload(black_box(&[0xAA; 64]))
                .build()
        })
    });
}

fn bench_build_tcp(c: &mut Criterion) {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    c.bench_function("build/tcp", |b| {
        b.iter(|| {
            TcpPacketBuilder::new()
                .source_port(12345)
                .destination_port(80)
                .sequence(1)
                .syn(true)
                .mss(1460)
                .build(src, dst)
        })
    });
}

criterion_group!(benches,
    bench_build_ipv4,
    bench_build_ethernet,
    bench_build_tcp,
);
criterion_main!(benches);
