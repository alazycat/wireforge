#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_app::dns::parser::DnsPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = DnsPacket::new(data) {
        let _ = pkt.transaction_id();
        let _ = pkt.flags();
        let _ = pkt.qr();
        let _ = pkt.opcode();
        for _ in pkt.questions() {}
        for _ in pkt.answers() {}
    }
});
