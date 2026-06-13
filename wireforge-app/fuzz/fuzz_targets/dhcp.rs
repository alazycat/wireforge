#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_app::dhcp::parser::DhcpPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = DhcpPacket::new(data) {
        let _ = pkt.op();
        let _ = pkt.xid();
        let _ = pkt.message_type();
        for _ in pkt.options() {}
    }
});
