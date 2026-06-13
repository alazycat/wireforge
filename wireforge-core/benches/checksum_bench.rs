use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wireforge_core::util::internet_checksum;

fn bench_checksum_small(c: &mut Criterion) {
    let data = [0x45u8, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xAC, 0x10, 0x0A, 0x63,
        0xAC, 0x10, 0x0A, 0x0C];
    c.bench_function("checksum/ip_header_20b", |b| {
        b.iter(|| internet_checksum(black_box(&data)))
    });
}

fn bench_checksum_large(c: &mut Criterion) {
    let data = [0xAAu8; 1500];
    c.bench_function("checksum/1500b", |b| {
        b.iter(|| internet_checksum(black_box(&data)))
    });
}

fn bench_checksum_empty(c: &mut Criterion) {
    let data: [u8; 0] = [];
    c.bench_function("checksum/empty", |b| {
        b.iter(|| internet_checksum(black_box(&data)))
    });
}

criterion_group!(benches,
    bench_checksum_small,
    bench_checksum_large,
    bench_checksum_empty,
);
criterion_main!(benches);
