//! TLS (Transport Layer Security) protocol parsing — ClientHello and SNI extraction.
//!
//! Supports TLS 1.0 through TLS 1.3. Three-layer parsing: Record → Handshake → ClientHello.

mod record;
mod handshake;
mod client_hello;
mod extensions;

pub use record::TlsRecord;
pub use handshake::TlsHandshake;
pub use client_hello::TlsClientHello;
pub use extensions::{TlsExtension, TlsExtensionsIter};
