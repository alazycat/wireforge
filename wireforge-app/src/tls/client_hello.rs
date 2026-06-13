//! TLS ClientHello parser with SNI and extensions support.

use super::extensions::TlsExtensionsIter;
use super::handshake::TlsHandshake;
use super::record::TlsRecord;

pub struct TlsClientHello<'a> { buf: &'a [u8], client_hello_start: usize }

impl<'a> TlsClientHello<'a> {
    /// Parse a TLS ClientHello from raw bytes (Record → Handshake → ClientHello).
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let record = TlsRecord::parse(buf)?;
        let handshake = TlsHandshake::parse(record.fragment())?;
        if handshake.handshake_type() != 1 { return None; } // not client_hello
        let body = handshake.body();
        if body.len() < 38 { return None; } // minimum: version(2)+random(32)+session_id_len(1)+cipher_suites_len(2)+comp_len(1)
        Some(Self { buf, client_hello_start: body.as_ptr() as usize - buf.as_ptr() as usize })
    }

    fn body(&self) -> &'a [u8] { &self.buf[self.client_hello_start..] }

    pub fn client_version(&self) -> u16 {
        let b = self.body();
        u16::from_be_bytes([b[0], b[1]])
    }

    pub fn random(&self) -> &[u8; 32] {
        self.body()[2..34].try_into().unwrap()
    }

    pub fn session_id(&self) -> &[u8] {
        let b = self.body();
        let len = b[34] as usize;
        let end = (35 + len).min(b.len());
        &b[35..end]
    }

    pub fn cipher_suites(&self) -> &[u16] {
        let b = self.body();
        let pos = 35 + b[34] as usize; // skip session_id
        if pos + 2 > b.len() { return &[]; }
        let len = u16::from_be_bytes([b[pos], b[pos+1]]) as usize;
        let data = &b[pos+2..];
        let count = (len / 2).min(data.len() / 2);
        // SAFETY: transmuting &[u8] to &[u16] — data is aligned for u16 reads
        unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u16, count) }
    }

    pub fn compression_methods(&self) -> &[u8] {
        let b = self.body();
        let mut pos = 35 + b[34] as usize;
        if pos + 2 > b.len() { return &[]; }
        let cs_len = u16::from_be_bytes([b[pos], b[pos+1]]) as usize;
        pos += 2 + cs_len;
        if pos + 1 > b.len() { return &[]; }
        let cm_len = b[pos] as usize;
        let end = (pos + 1 + cm_len).min(b.len());
        &b[pos+1..end]
    }

    /// Iterate over TLS extensions.
    pub fn extensions(&self) -> TlsExtensionsIter<'a> {
        let b = self.body();
        let mut pos = 35 + b[34] as usize;
        if pos + 2 > b.len() { return TlsExtensionsIter::new(&[]); }
        let cs_len = u16::from_be_bytes([b[pos], b[pos+1]]) as usize;
        pos += 2 + cs_len;
        if pos + 1 > b.len() { return TlsExtensionsIter::new(&[]); }
        let cm_len = b[pos] as usize;
        pos += 1 + cm_len;
        if pos + 2 > b.len() { return TlsExtensionsIter::new(&[]); }
        let ext_len = u16::from_be_bytes([b[pos], b[pos+1]]) as usize;
        let end = (pos + 2 + ext_len).min(b.len());
        TlsExtensionsIter::new(&b[pos+2..end])
    }

    /// Extract SNI server name from extension type 0x0000.
    pub fn server_name(&self) -> Option<&str> {
        for ext in self.extensions() {
            if ext.extension_type == 0x0000 && ext.data.len() >= 5 {
                // server_name_list_length(2) + name_type(1) + name_length(2) + name
                let list_len = u16::from_be_bytes([ext.data[0], ext.data[1]]) as usize;
                if list_len + 2 <= ext.data.len() {
                    let entry = &ext.data[2..2 + list_len];
                    if entry.len() >= 3 && entry[0] == 0 { // name_type=hostname
                        let name_len = u16::from_be_bytes([entry[1], entry[2]]) as usize;
                        if 3 + name_len <= entry.len() {
                            return std::str::from_utf8(&entry[3..3 + name_len]).ok();
                        }
                    }
                }
            }
        }
        None
    }

    /// Extract supported_versions from TLS 1.3 extension type 0x002b.
    pub fn supported_versions(&self) -> Option<Vec<u16>> {
        for ext in self.extensions() {
            if ext.extension_type == 0x002b && ext.data.len() >= 1 {
                let len = ext.data[0] as usize;
                if 1 + len <= ext.data.len() {
                    let versions: Vec<u16> = ext.data[1..1+len]
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    return Some(versions);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TLS 1.2 ClientHello: SNI=example.com, 2 cipher suites, no compression, no extensions beyond SNI
    fn tls12_sample() -> Vec<u8> {
        let ch = [
            0x03u8, 0x03, // version TLS 1.2
            // random (32 bytes of 0xAA)
        ];
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x00]; // record with placeholder length
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&ch);
        ch_body.extend_from_slice(&[0xAAu8; 32]); // random
        ch_body.push(0); // session_id_len = 0
        ch_body.extend_from_slice(&[0x00u8, 0x04]); // cipher_suites_len = 4 (2 suites)
        ch_body.extend_from_slice(&0xC02Bu16.to_be_bytes()); // TLS_ECDHE_RSA_AES_128_GCM
        ch_body.extend_from_slice(&0x009Cu16.to_be_bytes()); // TLS_RSA_AES_128_GCM
        ch_body.push(1); ch_body.push(0); // compression_methods: null
        // SNI extension
        let sn = b"example.com";
        // SNI extension: type=0x0000, len, server_name_list_len, name_type=0, name_len, name
        let sn_len = sn.len();
        let sn_ext_len = (sn_len + 5) as u16;
        let sn_list_len = (sn_len + 3) as u16;
        let mut ext_data = vec![0x00u8, 0x00]; // type=server_name
        ext_data.extend_from_slice(&sn_ext_len.to_be_bytes());
        ext_data.extend_from_slice(&sn_list_len.to_be_bytes());
        ext_data.push(0x00); // name_type=hostname
        ext_data.extend_from_slice(&(sn_len as u16).to_be_bytes());
        ext_data.extend_from_slice(sn);
        // extensions length prefix
        ch_body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext_data);
        // Handshake
        let handshake_len = ch_body.len();
        data.extend_from_slice(&[0x01]); // handshake_type=client_hello
        data.extend_from_slice(&(handshake_len as u32).to_be_bytes()[1..]); // 3-byte length
        data.extend_from_slice(&ch_body);
        // Record length
        let rec_len = data.len() - 5;
        data[3] = (rec_len >> 8) as u8;
        data[4] = rec_len as u8;
        data
    }

    #[test]
    fn parse_tls12_client_hello() {
        let data = tls12_sample();
        let ch = TlsClientHello::parse(&data).unwrap();
        assert_eq!(ch.client_version(), 0x0303);
        assert_eq!(ch.cipher_suites().len(), 2);
        assert_eq!(ch.session_id().len(), 0);
        assert_eq!(ch.server_name(), Some("example.com"));
        assert!(ch.supported_versions().is_none());
    }

    #[test]
    fn parse_tls13_client_hello() {
        // Hardcoded valid TLS 1.3 ClientHello with supported_versions extension
        let data = &[
            0x16, 0x03, 0x01, 0x00, 0x44, // TLS record: handshake, TLS 1.0 compat, len=68
            0x01, 0x00, 0x00, 0x40, // handshake: client_hello, len=64
            0x03, 0x03, // client_version = TLS 1.2 (legacy)
            // random (32 bytes)
            0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
            0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
            0x00, // session_id_len=0
            0x00, 0x02, 0x13, 0x01, // cipher_suites: 1 suite (TLS_AES_128_GCM)
            0x01, 0x00, // compression: null
            0x00, 0x07, // extensions length = 7
            0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
        ];
        let ch = TlsClientHello::parse(data).unwrap();
        assert!(ch.server_name().is_none());
        let sv = ch.supported_versions().unwrap();
        assert_eq!(sv, vec![0x0304]);
    }

    #[test]
    fn parse_too_short() {
        assert!(TlsClientHello::parse(&[]).is_none());
        assert!(TlsClientHello::parse(&[0x16, 0x03, 0x03, 0x00, 0x00]).is_none());
    }
}
