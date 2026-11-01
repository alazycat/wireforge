//! Tests for datalink configuration types.

use std::time::Duration;

use wireforge_io::{Config, FanoutOption, FanoutType};

#[test]
fn default_config_matches_wireforge_defaults() {
    let config = Config::default();

    assert_eq!(config.read_buffer_size, 65536);
    assert_eq!(config.write_buffer_size, 65536);
    assert_eq!(config.read_timeout, None);
    assert_eq!(config.write_timeout, None);
    assert!(!config.promiscuous);
    assert_eq!(config.socket_fd, None);
    assert_eq!(config.bpf_fd_attempts, 1000);
    assert_eq!(config.linux_fanout, None);
}

#[test]
fn config_and_fanout_are_copyable() {
    let fanout = FanoutOption {
        group_id: 7,
        fanout_type: FanoutType::Cpu,
        defrag: true,
        rollover: false,
    };
    let config = Config {
        read_timeout: Some(Duration::from_millis(25)),
        linux_fanout: Some(fanout),
        ..Config::default()
    };

    let copy = config;
    assert_eq!(copy.read_timeout, Some(Duration::from_millis(25)));
    assert_eq!(copy.linux_fanout, Some(fanout));
    assert_eq!(config.read_timeout, Some(Duration::from_millis(25)));
}
