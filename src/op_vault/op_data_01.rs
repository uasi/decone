use base64;

use op_vault::key::Key;

const HEADER_LEN: usize = 8;
const PLAINTEXT_LEN_LEN: usize = 8;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
const MIN_OP_DATA_01_LEN: usize = HEADER_LEN + PLAINTEXT_LEN_LEN + IV_LEN + MAC_LEN;

#[derive(Clone, Debug)]
pub struct OpData01 {
    bytes: Vec<u8>,
    plaintext_len: usize,
}

impl OpData01 {
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < MIN_OP_DATA_01_LEN || &bytes[0..HEADER_LEN] != b"opdata01" {
            return None;
        }
        Some(OpData01::from_bytes_unchecked(bytes))
    }

    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        assert!(bytes.len() >= MIN_OP_DATA_01_LEN);
        let plaintext_len = u64_from_bytes_le(&bytes[8..16]);
        OpData01 {
            bytes: bytes,
            plaintext_len: plaintext_len as usize,
        }
    }

    pub fn from_base64_str(b64str: &str) -> Option<Self> {
        base64::u8de(b64str.as_bytes())
            .ok()
            .and_then(|bytes| OpData01::new(bytes))
    }

    pub fn validate_with_key(&self, key: &Key) -> bool {
        let payload_end = self.bytes.len().saturating_sub(MAC_LEN);
        let payload = &self.bytes[..payload_end];
        key.compute_mac(payload) == self.mac()
    }

    pub fn decrypt_with_key(&self, key: &Key) -> Option<Vec<u8>> {
        if !self.validate_with_key(key) {
            return None;
        }
        let padded_plaintext = key.decrypt_aes(self.iv(), &self.ciphertext());
        let start = padded_plaintext.len().saturating_sub(self.plaintext_len());
        Some(padded_plaintext[start..].to_vec())
    }

    fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    fn iv(&self) -> &[u8] {
        let start = HEADER_LEN + PLAINTEXT_LEN_LEN;
        let end = start + IV_LEN;
        &self.bytes[start..end]
    }

    fn ciphertext(&self) -> &[u8] {
        let start = HEADER_LEN + PLAINTEXT_LEN_LEN + IV_LEN;
        let end = self.bytes.len().saturating_sub(MAC_LEN);
        &self.bytes[start..end]
    }

    fn mac(&self) -> &[u8] {
        let start = self.bytes.len().saturating_sub(MAC_LEN);
        &self.bytes[start..]
    }
}

fn u64_from_bytes_le(bytes: &[u8]) -> u64 {
    assert!(bytes.len() == 8);
    let u64_le =
        (bytes[7] as u64) << 8 * 7 |
        (bytes[6] as u64) << 8 * 6 |
        (bytes[5] as u64) << 8 * 5 |
        (bytes[4] as u64) << 8 * 4 |
        (bytes[3] as u64) << 8 * 3 |
        (bytes[2] as u64) << 8 * 2 |
        (bytes[1] as u64) << 8 * 1 |
        (bytes[0] as u64);
    u64::from_le(u64_le)
}
