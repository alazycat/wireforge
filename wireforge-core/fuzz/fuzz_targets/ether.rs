#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::ether::EthernetPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = EthernetPacket::new(data) {
        let _ = pkt.dst_mac();
        let _ = pkt.src_mac();
        let _ = pkt.ethertype();
        let _ = pkt.payload();
    }
});
