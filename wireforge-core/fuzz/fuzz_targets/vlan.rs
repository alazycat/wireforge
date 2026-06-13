#![no_main]
use libfuzzer_sys::fuzz_target;
use wireforge_core::vlan::{VlanPacket, parse_vlan_chain};

fuzz_target!(|data: &[u8]| {
    if let Some(pkt) = VlanPacket::new(data) {
        let _ = pkt.pcp();
        let _ = pkt.dei();
        let _ = pkt.vid();
        let _ = pkt.ethertype();
        let _ = pkt.inner();
    }
    let _ = parse_vlan_chain(data);
});
