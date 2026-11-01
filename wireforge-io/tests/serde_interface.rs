//! Serde roundtrip tests for `Interface` / `IpNetwork` (enabled with the `serde` feature).
#![cfg(feature = "serde")]

use wireforge_io::{Interface, IpNetwork};

fn sample_interface() -> Interface {
    Interface {
        name: "eth0".to_string(),
        description: Some("Ethernet adapter".to_string()),
        friendly_name: Some("Ethernet".to_string()),
        index: 7,
        mac_address: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        ips: vec!["192.168.1.10".parse().unwrap()],
        ip_networks: vec![IpNetwork::new("192.168.1.10".parse().unwrap(), 24)],
        is_loopback: false,
        is_up: true,
        is_broadcast: true,
        is_point_to_point: false,
        is_multicast: true,
        is_running: true,
    }
}

#[test]
fn interface_serde_roundtrip() {
    let iface = sample_interface();

    let json = serde_json::to_string(&iface).unwrap();
    assert!(json.contains("\"name\":\"eth0\""));
    // `mac_address` stays `[u8; 6]` (API compatibility), so it serializes as an array.
    assert!(json.contains("[170,187,204,221,238,255]"));

    let parsed: Interface = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, iface.name);
    assert_eq!(parsed.mac_address, iface.mac_address);
    assert_eq!(parsed.ip_networks, iface.ip_networks);
    assert_eq!(parsed.is_up, iface.is_up);
}

#[test]
fn interface_serde_optional_fields() {
    let iface = Interface {
        name: "lo".to_string(),
        description: None,
        friendly_name: None,
        index: 1,
        mac_address: None,
        ips: vec![],
        ip_networks: vec![],
        is_loopback: true,
        is_up: true,
        is_broadcast: false,
        is_point_to_point: false,
        is_multicast: false,
        is_running: true,
    };

    let json = serde_json::to_string(&iface).unwrap();
    let parsed: Interface = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.description, None);
    assert_eq!(parsed.mac_address, None);
    assert!(parsed.is_loopback);
}

#[test]
fn ip_network_serde_roundtrip() {
    let net = IpNetwork::new("10.0.0.1".parse().unwrap(), 8);
    let json = serde_json::to_string(&net).unwrap();
    let parsed: IpNetwork = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, net);
    assert_eq!(parsed.netmask().to_string(), "255.0.0.0");
}
