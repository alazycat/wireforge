#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::icmp::IcmpPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = IcmpPacket::new(data) {
        let _ = pkt.type_();
        let _ = pkt.code();
        let _ = pkt.checksum();
        let _ = pkt.payload();
        let _ = pkt.verify_checksum();
        let _ = pkt.message();
    }
});
