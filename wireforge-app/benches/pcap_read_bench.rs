use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wireforge_app::pcap::PcapReader;

fn bench_pcap_read(c: &mut Criterion) {
    // Build a pcap file with 1000 packets in memory
    let mut data = Vec::new();
    data.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes());
    data.extend_from_slice(&2u16.to_be_bytes());
    data.extend_from_slice(&4u16.to_be_bytes());
    data.extend_from_slice(&[0u8; 8]);
    data.extend_from_slice(&65535u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes()); // Ethernet

    for i in 0..1000u32 {
        data.extend_from_slice(&i.to_be_bytes()); // ts_sec
        data.extend_from_slice(&0u32.to_be_bytes()); // ts_usec
        data.extend_from_slice(&64u32.to_be_bytes()); // incl_len
        data.extend_from_slice(&64u32.to_be_bytes()); // orig_len
        data.extend_from_slice(&[0xAAu8; 64]);
    }

    let data = black_box(data);

    c.bench_function("pcap/read_1000_packets", |b| {
        b.iter(|| {
            let reader = PcapReader::from_bytes(data.clone()).unwrap();
            let count = reader.count();
            assert_eq!(count, 1000);
        })
    });
}

criterion_group!(benches, bench_pcap_read);
criterion_main!(benches);
