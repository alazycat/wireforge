//! Tests for the in-memory dummy L2 backend.

use std::time::Duration;

use wireforge_io::dummy::l2_channel;
use wireforge_io::traits::{L2Reader, L2Writer};
use wireforge_io::IoError;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + payload.len()];
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame[12..14].copy_from_slice(&[0x88, 0xB5]);
    frame[14..].copy_from_slice(payload);
    frame
}

#[test]
fn writer_sends_frames_to_handle() {
    let (_reader, writer, handle) = l2_channel();
    let sent = frame(b"hello");

    let n = writer.send(&sent).expect("send should succeed");
    assert_eq!(n, sent.len());

    let observed = handle
        .recv_sent(Duration::from_secs(1))
        .expect("handle should receive the frame");
    assert_eq!(observed, sent);
}

#[test]
fn handle_injects_frames_into_reader() {
    let (mut reader, _writer, handle) = l2_channel();
    let injected = frame(b"injected");

    handle.inject(&injected).expect("inject should succeed");
    let packet = reader.recv().expect("reader should receive the frame");
    assert_eq!(packet.as_bytes(), injected.as_slice());
}

#[test]
fn reader_preserves_fifo_order() {
    let (mut reader, _writer, handle) = l2_channel();
    let first = frame(&[1]);
    let second = frame(&[2]);

    handle.inject(&first).unwrap();
    handle.inject(&second).unwrap();

    {
        let packet = reader.recv().unwrap();
        assert_eq!(packet.as_bytes(), first.as_slice());
    }
    {
        let packet = reader.recv().unwrap();
        assert_eq!(packet.as_bytes(), second.as_slice());
    }
}

#[test]
fn reader_times_out_when_idle() {
    let (mut reader, _writer, _handle) = l2_channel();
    reader
        .set_timeout(Some(Duration::from_millis(50)))
        .expect("set_timeout should succeed");
    assert_eq!(reader.timeout(), Some(Duration::from_millis(50)));

    match reader.recv() {
        Err(IoError::Timeout) => {}
        Ok(_) => panic!("expected a timeout, got a packet"),
        Err(e) => panic!("expected a timeout, got {e}"),
    }
}

#[test]
fn short_frame_is_rejected() {
    let (mut reader, _writer, handle) = l2_channel();
    handle.inject(&[0u8; 3]).unwrap();

    match reader.recv() {
        Err(IoError::Parse(_)) => {}
        Ok(_) => panic!("expected a parse error, got a packet"),
        Err(e) => panic!("expected a parse error, got {e}"),
    }
}

#[test]
fn promiscuous_mode_is_a_noop() {
    let (mut reader, _writer, handle) = l2_channel();
    assert!(!reader.is_promiscuous());
    reader.set_promiscuous(true).unwrap();
    assert!(reader.is_promiscuous());
    reader.set_promiscuous(false).unwrap();
    assert!(!reader.is_promiscuous());

    let injected = frame(b"x");
    handle.inject(&injected).unwrap();
    assert_eq!(reader.recv().unwrap().as_bytes(), injected.as_slice());
}

#[test]
fn injected_error_is_returned_by_reader() {
    let (mut reader, _writer, handle) = l2_channel();
    handle.inject_error(IoError::Timeout).unwrap();

    match reader.recv() {
        Err(IoError::Timeout) => {}
        Ok(_) => panic!("expected the injected error, got a packet"),
        Err(e) => panic!("expected the injected error, got {e}"),
    }
}

#[test]
fn writer_reports_closed_handle() {
    let (_reader, writer, handle) = l2_channel();
    drop(handle);

    match writer.send(&frame(b"x")) {
        Err(IoError::Socket(_)) => {}
        Ok(_) => panic!("expected a send error"),
        Err(e) => panic!("expected a socket error, got {e}"),
    }
}

#[test]
fn handle_reports_closed_reader() {
    let (reader, _writer, handle) = l2_channel();
    drop(reader);

    match handle.inject(&frame(b"x")) {
        Err(IoError::Socket(_)) => {}
        Ok(()) => panic!("expected an inject error"),
        Err(e) => panic!("expected a socket error, got {e}"),
    }
}

#[test]
fn try_recv_sent_returns_none_when_empty() {
    let (_reader, _writer, handle) = l2_channel();
    assert!(handle.try_recv_sent().is_none());
}

#[test]
fn recv_sent_times_out_when_empty() {
    let (_reader, _writer, handle) = l2_channel();

    match handle.recv_sent(Duration::from_millis(50)) {
        Err(IoError::Timeout) => {}
        Ok(_) => panic!("expected a timeout, got a frame"),
        Err(e) => panic!("expected a timeout, got {e}"),
    }
}

#[test]
fn recv_sent_reports_closed_writer() {
    let (_reader, writer, handle) = l2_channel();
    drop(writer);

    match handle.recv_sent(Duration::from_millis(50)) {
        Err(IoError::Socket(_)) => {}
        Ok(_) => panic!("expected a closed-channel error, got a frame"),
        Err(e) => panic!("expected a closed-channel error, got {e}"),
    }
}
