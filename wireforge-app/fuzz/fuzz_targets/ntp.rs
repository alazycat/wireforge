#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_app::ntp::parser::NtpPacket;

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = NtpPacket::new(data) {
        let _ = pkt.leap();
        let _ = pkt.version();
        let _ = pkt.mode();
        let _ = pkt.stratum();
        let _ = pkt.transmit_timestamp();
    }
});
