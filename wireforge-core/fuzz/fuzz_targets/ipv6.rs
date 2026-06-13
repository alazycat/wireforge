#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::ipv6::Ipv6Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = Ipv6Packet::new(data) {
        let _ = pkt.version();
        let _ = pkt.traffic_class();
        let _ = pkt.flow_label();
        let _ = pkt.payload_length();
        let _ = pkt.next_header();
        let _ = pkt.hop_limit();
        let _ = pkt.source();
        let _ = pkt.destination();
        let _ = pkt.final_protocol();
        let _ = pkt.payload();
        for _ in pkt.extension_headers() {}
    }
});
