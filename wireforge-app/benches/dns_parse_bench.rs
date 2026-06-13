use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wireforge_app::dns::parser::DnsPacket;

fn bench_dns_parse(c: &mut Criterion) {
    // Build a sample DNS response
    let data = wireforge_app::dns::builder::DnsPacketBuilder::response()
        .transaction_id(0x1234)
        .add_question("www.example.com", wireforge_app::dns::types::DnsType::A, wireforge_app::dns::types::DnsClass::IN)
        .add_raw_answer("www.example.com", wireforge_app::dns::types::DnsType::A, 300, &[192, 168, 1, 1])
        .build();

    c.bench_function("dns/parse_response", |b| {
        b.iter(|| {
            let pkt = DnsPacket::new(black_box(&data)).unwrap();
            let _: Vec<_> = pkt.answers().collect();
        })
    });
}

criterion_group!(benches, bench_dns_parse);
criterion_main!(benches);
