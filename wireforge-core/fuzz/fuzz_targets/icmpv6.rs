#![no_main]
use libfuzzer_sys::fuzz_target;
use core::net::Ipv6Addr;
use wireforge_core::icmp::Icmpv6Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = Icmpv6Packet::new(data) {
        let _ = pkt.type_();
        let _ = pkt.code();
        let _ = pkt.checksum();
        let _ = pkt.body();
        let _ = pkt.message();
    }
});
