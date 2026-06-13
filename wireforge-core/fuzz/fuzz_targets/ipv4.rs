#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::ipv4::Ipv4Packet;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = Ipv4Packet::new(data) {
        let _ = pkt.version();
        let _ = pkt.ihl();
        let _ = pkt.dscp();
        let _ = pkt.ecn();
        let _ = pkt.total_length();
        let _ = pkt.identification();
        let _ = pkt.flags();
        let _ = pkt.fragment_offset();
        let _ = pkt.ttl();
        let _ = pkt.protocol();
        let _ = pkt.checksum();
        let _ = pkt.source();
        let _ = pkt.destination();
        let _ = pkt.options();
        let _ = pkt.payload();
        let _ = pkt.header_length();
        let _ = pkt.verify_checksum();
    }
});
