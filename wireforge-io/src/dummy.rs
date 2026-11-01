//! In-memory dummy L2 backend for tests.
//!
//! The backend uses FIFO channels instead of a real network interface, so it
//! needs no privileges and no hardware. A [`l2_channel`] pair is connected to a
//! [`DummyL2Handle`], which can inject frames into the reader and observe frames
//! sent by the writer.
//!
//! ```
//! use std::time::Duration;
//!
//! use wireforge_io::dummy::l2_channel;
//! use wireforge_io::traits::{L2Reader, L2Writer};
//!
//! let (mut reader, writer, handle) = l2_channel();
//! let frame = vec![0u8; 14];
//!
//! // Frames sent by the writer are visible on the handle.
//! writer.send(&frame).unwrap();
//! assert_eq!(handle.recv_sent(Duration::from_secs(1)).unwrap(), frame);
//!
//! // Frames injected on the handle are visible to the reader.
//! handle.inject(&frame).unwrap();
//! assert_eq!(reader.recv().unwrap().as_bytes(), frame.as_slice());
//! ```

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use wireforge_core::ether::EthernetPacket;

use crate::error::IoError;
use crate::traits::{L2Reader, L2Writer};

fn channel_closed(what: &'static str) -> IoError {
    IoError::Socket(std::io::Error::new(std::io::ErrorKind::BrokenPipe, what))
}

/// Create an in-memory L2 reader/writer pair plus the test handle.
///
/// The returned tuple is `(reader, writer, handle)`:
/// - `reader` yields frames injected through the handle;
/// - `writer` sends frames to the handle;
/// - `handle` provides [`inject`](DummyL2Handle::inject),
///   [`inject_error`](DummyL2Handle::inject_error),
///   [`recv_sent`](DummyL2Handle::recv_sent), and
///   [`try_recv_sent`](DummyL2Handle::try_recv_sent).
pub fn l2_channel() -> (DummyL2Reader, DummyL2Writer, DummyL2Handle) {
    let (inject_tx, inject_rx) = mpsc::channel();
    let (sent_tx, sent_rx) = mpsc::channel();

    (
        DummyL2Reader {
            rx: inject_rx,
            timeout: None,
            promiscuous: false,
            last_frame: Vec::new(),
        },
        DummyL2Writer { tx: sent_tx },
        DummyL2Handle { inject_tx, sent_rx },
    )
}

/// Reader half of the dummy L2 backend.
pub struct DummyL2Reader {
    rx: Receiver<Result<Vec<u8>, IoError>>,
    timeout: Option<Duration>,
    promiscuous: bool,
    /// Owns the most recently received frame so `recv` can return a borrowed
    /// `EthernetPacket`.
    last_frame: Vec<u8>,
}

impl DummyL2Reader {
    /// Whether promiscuous mode was last enabled.
    pub fn is_promiscuous(&self) -> bool {
        self.promiscuous
    }

    /// The configured receive timeout.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

impl L2Reader for DummyL2Reader {
    fn recv(&mut self) -> Result<EthernetPacket<'_>, IoError> {
        let frame = match self.timeout {
            Some(timeout) => match self.rx.recv_timeout(timeout) {
                Ok(item) => item?,
                Err(RecvTimeoutError::Timeout) => return Err(IoError::Timeout),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(channel_closed("dummy reader channel closed"))
                }
            },
            None => match self.rx.recv() {
                Ok(item) => item?,
                Err(_) => return Err(channel_closed("dummy reader channel closed")),
            },
        };

        self.last_frame = frame;
        EthernetPacket::new(&self.last_frame).ok_or(IoError::Parse("invalid Ethernet frame"))
    }

    fn set_timeout(&mut self, dur: Option<Duration>) -> Result<(), IoError> {
        self.timeout = dur;
        Ok(())
    }

    fn set_promiscuous(&mut self, on: bool) -> Result<(), IoError> {
        self.promiscuous = on;
        Ok(())
    }
}

/// Writer half of the dummy L2 backend.
pub struct DummyL2Writer {
    tx: Sender<Vec<u8>>,
}

impl L2Writer for DummyL2Writer {
    fn send(&self, packet: &[u8]) -> Result<usize, IoError> {
        self.tx
            .send(packet.to_vec())
            .map_err(|_| channel_closed("dummy handle dropped"))?;
        Ok(packet.len())
    }
}

/// Test handle connected to a [`l2_channel`] pair.
pub struct DummyL2Handle {
    inject_tx: Sender<Result<Vec<u8>, IoError>>,
    sent_rx: Receiver<Vec<u8>>,
}

impl DummyL2Handle {
    /// Inject a frame into the reader.
    pub fn inject(&self, frame: &[u8]) -> Result<(), IoError> {
        self.inject_owned(frame.to_vec())
    }

    /// Inject an owned frame into the reader, avoiding a copy.
    pub fn inject_owned(&self, frame: Vec<u8>) -> Result<(), IoError> {
        self.inject_tx
            .send(Ok(frame))
            .map_err(|_| channel_closed("dummy reader dropped"))
    }

    /// Inject an error into the reader, simulating a network failure.
    pub fn inject_error(&self, error: IoError) -> Result<(), IoError> {
        self.inject_tx
            .send(Err(error))
            .map_err(|_| channel_closed("dummy reader dropped"))
    }

    /// Receive the next frame sent by the writer, waiting up to `timeout`.
    pub fn recv_sent(&self, timeout: Duration) -> Result<Vec<u8>, IoError> {
        match self.sent_rx.recv_timeout(timeout) {
            Ok(frame) => Ok(frame),
            Err(RecvTimeoutError::Timeout) => Err(IoError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(channel_closed("dummy writer dropped")),
        }
    }

    /// Return the next frame sent by the writer, if one is already queued.
    pub fn try_recv_sent(&self) -> Option<Vec<u8>> {
        self.sent_rx.try_recv().ok()
    }
}
