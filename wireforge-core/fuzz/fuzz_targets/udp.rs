#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::udp::UdpPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = UdpPacket::new(data) {
        let _ = pkt.source_port();
        let _ = pkt.destination_port();
        let _ = pkt.length();
        let _ = pkt.checksum();
        let _ = pkt.payload();
    }
});
