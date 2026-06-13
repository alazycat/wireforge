#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::arp::ArpPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = ArpPacket::new(data) {
        let _ = pkt.hardware_type();
        let _ = pkt.protocol_type();
        let _ = pkt.hw_addr_len();
        let _ = pkt.proto_addr_len();
        let _ = pkt.operation();
        let _ = pkt.sender_hw_addr();
        let _ = pkt.sender_proto_addr();
        let _ = pkt.target_hw_addr();
        let _ = pkt.target_proto_addr();
    }
});
