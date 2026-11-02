#![no_main]

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use wireforge_fuzz::surface;

fuzz_target!(|data: &[u8]| {
    let mut sink = 0u64;
    surface::dns(data, &mut sink);
    black_box(sink);
});
