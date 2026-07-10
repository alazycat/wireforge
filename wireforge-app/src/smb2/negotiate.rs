//! SMB2 negotiate protocol request and response parsers.

pub struct Smb2NegotiateRequest<'a> { buf: &'a [u8] }

impl<'a> Smb2NegotiateRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        // header(36) = struct_size(2) + dialect_count(2) + sec_mode(2) + reserved(2)
        //             + capabilities(4) + client_guid(16) + client_start_time(8)
        if buf.len() < 36 { return None; }
        if u16::from_le_bytes([buf[0], buf[1]]) != 36 { return None; }
        Some(Self { buf })
    }

    pub fn dialect_count(&self) -> u16 {
        u16::from_le_bytes([self.buf[2], self.buf[3]])
    }

    pub fn capabilities(&self) -> u32 {
        u32::from_le_bytes([self.buf[8], self.buf[9], self.buf[10], self.buf[11]])
    }

    /// 16-byte client GUID at offset 12.
    pub fn client_guid(&self) -> &[u8; 16] {
        self.buf[12..28].try_into().unwrap()
    }

    /// Dialects start at offset 36.
    pub fn dialects(&self) -> Vec<u16> {
        let cnt = self.dialect_count() as usize;
        (0..cnt)
            .filter_map(|i| {
                let off = 36 + i * 2;
                if off + 2 <= self.buf.len() {
                    Some(u16::from_le_bytes([self.buf[off], self.buf[off + 1]]))
                } else {
                    None
                }
            })
            .collect()
    }
}

pub struct Smb2NegotiateResponse<'a> { buf: &'a [u8] }

impl<'a> Smb2NegotiateResponse<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        // header(65) = struct_size(2) + sec_mode(2) + dialect_rev(2) + reserved(2)
        //             + server_guid(16) + capabilities(4) + max_transact(4) + max_read(4)
        //             + max_write(4) + system_time(8) + server_start_time(8)
        //             + sec_buf_offset(2) + sec_buf_len(2) + reserved2(4) + padding(1)
        if buf.len() < 65 { return None; }
        if u16::from_le_bytes([buf[0], buf[1]]) != 65 { return None; }
        Some(Self { buf })
    }

    pub fn dialect_revision(&self) -> u16 {
        u16::from_le_bytes([self.buf[4], self.buf[5]])
    }

    pub fn server_guid(&self) -> &[u8; 16] {
        self.buf[8..24].try_into().unwrap()
    }

    pub fn capabilities(&self) -> u32 {
        u32::from_le_bytes([self.buf[24], self.buf[25], self.buf[26], self.buf[27]])
    }

    pub fn max_transact_size(&self) -> u32 {
        u32::from_le_bytes([self.buf[28], self.buf[29], self.buf[30], self.buf[31]])
    }

    pub fn max_read_size(&self) -> u32 {
        u32::from_le_bytes([self.buf[32], self.buf[33], self.buf[34], self.buf[35]])
    }

    pub fn max_write_size(&self) -> u32 {
        u32::from_le_bytes([self.buf[36], self.buf[37], self.buf[38], self.buf[39]])
    }

    pub fn system_time(&self) -> u64 {
        u64::from_le_bytes([
            self.buf[40], self.buf[41], self.buf[42], self.buf[43],
            self.buf[44], self.buf[45], self.buf[46], self.buf[47],
        ])
    }

    pub fn server_start_time(&self) -> u64 {
        u64::from_le_bytes([
            self.buf[48], self.buf[49], self.buf[50], self.buf[51],
            self.buf[52], self.buf[53], self.buf[54], self.buf[55],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_negotiate_request() {
        let mut body = vec![36u8, 0, 4, 0, 0, 0, 0, 0]; // sz+count+sec_mode+reserved
        body.extend_from_slice(&1u32.to_le_bytes()); // capabilities (offset 8)
        body.extend_from_slice(&[0xAAu8; 16]); // client_guid (offset 12)
        body.extend_from_slice(&0u64.to_le_bytes()); // client_start_time (offset 28)
        body.extend_from_slice(&0x0202u16.to_le_bytes()); // dialects (offset 36)
        body.extend_from_slice(&0x0210u16.to_le_bytes());
        body.extend_from_slice(&0x0300u16.to_le_bytes());
        body.extend_from_slice(&0x0311u16.to_le_bytes());
        let req = Smb2NegotiateRequest::parse(&body).unwrap();
        assert_eq!(req.dialect_count(), 4);
        assert_eq!(req.dialects(), vec![0x0202, 0x0210, 0x0300, 0x0311]);
    }

    #[test]
    fn parse_negotiate_response() {
        let mut body = vec![65u8, 0, 0, 0, 0x11, 0x03, 0, 0]; // sz+sec+rev+reserved
        body.extend_from_slice(&[0u8; 16]); // server_guid (offset 8)
        body.extend_from_slice(&0u32.to_le_bytes()); // capabilities (offset 24)
        body.extend_from_slice(&65536u32.to_le_bytes()); // max_transact (offset 28)
        body.extend_from_slice(&65536u32.to_le_bytes()); // max_read (offset 32)
        body.extend_from_slice(&65536u32.to_le_bytes()); // max_write (offset 36)
        body.extend_from_slice(&0u64.to_le_bytes()); // system_time (offset 40)
        body.extend_from_slice(&0u64.to_le_bytes()); // server_start_time (offset 48)
        body.extend_from_slice(&[0u8; 9]); // sec_buf_off+len+reserved2 + 1 byte padding
        let resp = Smb2NegotiateResponse::parse(&body).unwrap();
        assert_eq!(resp.dialect_revision(), 0x0311);
        assert_eq!(resp.max_read_size(), 65536);
    }
}
