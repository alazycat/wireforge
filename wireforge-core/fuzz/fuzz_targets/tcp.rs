#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::tcp::TcpPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = TcpPacket::new(data) {
        let _ = pkt.source_port();
        let _ = pkt.destination_port();
        let _ = pkt.sequence();
        let _ = pkt.ack_number();
        let _ = pkt.data_offset();
        let _ = pkt.flags();
        let _ = pkt.syn();
        let _ = pkt.ack();
        let _ = pkt.fin();
        let _ = pkt.rst();
        let _ = pkt.psh();
        let _ = pkt.urg();
        let _ = pkt.window();
        let _ = pkt.checksum();
        let _ = pkt.urgent_pointer();
        let _ = pkt.payload();
        let _ = pkt.header_length();
        for _ in pkt.options() {}
    }
});
