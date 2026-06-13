//! SSH binary packet and key exchange init parser (RFC 4253 §6, §7.1).

pub struct SshBinaryPacket<'a> { buf: &'a [u8], payload_start: usize, payload_len: usize }

impl<'a> SshBinaryPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 5 { return None; }
        let packet_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let padding_len = buf[4] as usize;
        let payload_len = packet_len.saturating_sub(padding_len).saturating_sub(1);
        Some(Self { buf, payload_start: 5, payload_len })
    }

    pub fn packet_length(&self) -> u32 { u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) }
    pub fn padding_length(&self) -> u8 { self.buf[4] }
    pub fn payload(&self) -> &'a [u8] {
        let end = (self.payload_start + self.payload_len).min(self.buf.len());
        &self.buf[self.payload_start..end]
    }
}

pub struct SshKexInit<'a> { payload: &'a [u8], cursor: usize }

impl<'a> SshKexInit<'a> {
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let pkt = SshBinaryPacket::parse(buf)?;
        let payload = pkt.payload();
        if payload.is_empty() || payload[0] != 20 { return None; }
        if payload.len() < 17 { return None; }
        Some(Self { payload, cursor: 17 }) // skip type(1) + cookie(16)
    }

    pub fn cookie(&self) -> &[u8; 16] {
        self.payload[1..17].try_into().unwrap()
    }

    fn next_name_list(&mut self) -> Vec<String> {
        let data = &self.payload[self.cursor..];
        if data.len() < 4 { return vec![]; }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        self.cursor += 4;
        let end = (self.cursor + len).min(self.payload.len());
        let list_bytes = &self.payload[self.cursor..end];
        self.cursor = end;
        if list_bytes.is_empty() { return vec![]; }
        std::str::from_utf8(list_bytes).unwrap_or("").split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    }

    pub fn kex_algorithms(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn server_host_key_algorithms(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn encryption_algorithms_cts(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn encryption_algorithms_stc(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn mac_algorithms_cts(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn mac_algorithms_stc(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn compression_algorithms_cts(&mut self) -> Vec<String> { self.next_name_list() }
    pub fn compression_algorithms_stc(&mut self) -> Vec<String> { self.next_name_list() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kex_init() {
        let cookie = [0xAAu8; 16];
        let name_list = b"curve25519-sha256";
        let nl_len = name_list.len() as u32;
        let mut payload = vec![20u8];
        payload.extend_from_slice(&cookie);
        for _ in 0..8 {
            payload.extend_from_slice(&nl_len.to_be_bytes());
            payload.extend_from_slice(name_list);
        }
        payload.push(0);
        payload.extend_from_slice(&[0u8; 4]);

        let packet_len = 1 + payload.len() + 4; // padding_len + payload + padding
        let mut pkt = vec![];
        pkt.extend_from_slice(&(packet_len as u32).to_be_bytes());
        pkt.push(4); // padding_length
        pkt.extend_from_slice(&payload);
        pkt.extend_from_slice(&[0u8; 4]); // padding

        let mut kex = SshKexInit::parse(&pkt).unwrap();
        assert_eq!(kex.cookie(), &cookie);
        assert_eq!(kex.kex_algorithms(), vec!["curve25519-sha256".to_string()]);
    }
}
