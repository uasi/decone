use openssl::crypto::{hash, hmac, pkcs5, symm};

const HEADER_LEN: usize = 8;
const PLAINTEXT_LEN_LEN: usize = 8;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;
const MIN_OP_DATA_01_LEN: usize = HEADER_LEN + PLAINTEXT_LEN_LEN + IV_LEN + MAC_LEN;

pub struct OpData01 {
    bytes: Vec<u8>,
    plaintext_len: usize,
}

impl OpData01 {
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        assert!(bytes.len() > MIN_OP_DATA_01_LEN);
        if &bytes[0..HEADER_LEN] == b"opdata01" {
            Some(OpData01::from_bytes_unchecked(bytes))
        } else {
            None
        }
    }

    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        let plaintext_len = u64_from_bytes_le(&bytes[8..16]);
        OpData01 {
            bytes: bytes,
            plaintext_len: plaintext_len as usize,
        }
    }

    pub fn plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    pub fn iv(&self) -> &[u8] {
        let start = HEADER_LEN + PLAINTEXT_LEN_LEN;
        let end = start + IV_LEN;
        &self.bytes[start..end]
    }

    pub fn ciphertext(&self) -> &[u8] {
        let start = HEADER_LEN + PLAINTEXT_LEN_LEN + IV_LEN;
        let end = self.bytes.len().saturating_sub(MAC_LEN);
        &self.bytes[start..end]
    }

    pub fn mac(&self) -> &[u8] {
        let start = self.bytes.len().saturating_sub(MAC_LEN);
        &self.bytes[start..]
    }

    pub fn validate(&self, key: &Key) -> bool {
        let payload_end = self.bytes.len().saturating_sub(MAC_LEN);
        let payload = &self.bytes[..payload_end];
        key.compute_mac(payload) == self.mac()
    }

    pub fn decrypt(&self, key: &Key) -> Vec<u8> {
        let padded_plaintext = key.decrypt_aes(self.iv(), &self.ciphertext());
        let start = padded_plaintext.len().saturating_sub(self.plaintext_len());
        padded_plaintext[start..].to_vec()
    }
}

pub trait Key {
    fn enc_key(&self) -> &[u8];
    fn mac_key(&self) -> &[u8];

    fn compute_mac(&self, bytes: &[u8]) -> Vec<u8> {
        hmac::hmac(hash::Type::SHA256, self.mac_key(), bytes)
    }

    fn decrypt_aes(&self, iv: &[u8], bytes: &[u8]) -> Vec<u8> {
        let crypter = symm::Crypter::new(symm::Type::AES_256_CBC);
        crypter.init(symm::Mode::Decrypt, self.enc_key(), iv);
        crypter.pad(false);
        let mut plaintext = crypter.update(bytes);
        plaintext.extend(crypter.finalize());
        plaintext
    }
}

#[derive(Clone, Debug)]
pub struct MainKey {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}

impl Key for MainKey {
    fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }
}

impl MainKey {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        MainKey {
            enc_key: enc_key,
            mac_key: mac_key,
        }
    }

    pub fn from_op_data(key: &DerivedKey, op_data: &OpData01) -> Self {
        let plaintext = op_data.decrypt(key);
        let bytes = hash::hash(hash::Type::SHA512, &plaintext);
        let enc_key = bytes[0..32].to_vec();
        let mac_key = bytes[32..64].to_vec();
        MainKey::new(enc_key, mac_key)
    }
}

#[derive(Clone, Debug)]
pub struct DerivedKey {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}

impl Key for DerivedKey {
    fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }
}

impl DerivedKey {
    pub fn new(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        DerivedKey {
            enc_key: enc_key,
            mac_key: mac_key,
        }
    }

    pub fn from_password(password: &str, salt: &[u8], iterations: usize) -> Self {
        let bytes_len = 64;
        let bytes = pkcs5::pbkdf2_hmac_sha512(password, salt, iterations, bytes_len);
        let enc_key = bytes[0..32].to_vec();
        let mac_key = bytes[32..64].to_vec();
        DerivedKey::new(enc_key, mac_key)
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

#[cfg(test)]
mod tests {
    use base64;
    use super::Key;

    const DEMO_PASSWORD: &'static str = "freddy";
    const DEMO_SALT: &'static str = "P0pOMMN6Ow5wIKOOSsaSQg==";
    const DEMO_ITERATIONS: usize = 50_000;
    const DEMO_OVERVIEW_KEY: &'static str = "b3BkYXRhMDFAAAAAAAAAAIy1hZwIGeiLn4mLE1R8lEwIOye95GEyfZcPKlyXkkb0IBTfCXM+aDxjD7hOliuTM/YMIqxK+firVvW3c5cp2QMgvQHpDW2AsAQpBqcgBgRUCSP+THMVg15ZeR9lI77mHBpTQ70D+bchvkSmw3hoEGot7YcnQCATbouhMXIMO52D";
    const DEMO_OVERVIEW:  &'static str = "b3BkYXRhMDESAAAAAAAAAHw2J+nRQ2h7a9jZ8kH4ser/wKowBqgkJxv+RPujmrB7X53ooYk2wxyfiM2par2J44pCxLcNesV9F+jFCIecxGouN+3F033Ktzm3fKC2pGXy"; // from sample folder 379A3A7E5D5A47A6AA3A69C4D1E57D1B
    const DEMO_OVERVIEW_DECRYPTED: &'static str = r#"{"title":"Social"}"#;

    #[test]
    fn test_validate() {
        let salt = base64::u8de(DEMO_SALT.as_bytes()).unwrap();
        let derived_key = super::DerivedKey::from_password(&DEMO_PASSWORD, &salt, DEMO_ITERATIONS);

        let raw_overview_key_data = base64::u8de(DEMO_OVERVIEW_KEY.as_bytes()).unwrap();
        let overview_key_data = super::OpData01::new(raw_overview_key_data).unwrap();

        assert!(overview_key_data.validate(&derived_key));
    }

    #[test]
    fn test_decrypt() {
        let salt = base64::u8de(DEMO_SALT.as_bytes()).unwrap();
        let derived_key = super::DerivedKey::from_password(&DEMO_PASSWORD, &salt, DEMO_ITERATIONS);

        let raw_overview_key_data = base64::u8de(DEMO_OVERVIEW_KEY.as_bytes()).unwrap();
        let overview_key_data = super::OpData01::new(raw_overview_key_data).unwrap();
        let overview_key = super::MainKey::from_op_data(&derived_key, &overview_key_data);

        let raw_overview_data = base64::u8de(DEMO_OVERVIEW.as_bytes()).unwrap();
        let overview_data = super::OpData01::new(raw_overview_data).unwrap();

        assert!(overview_data.validate(&overview_key));

        let overview = overview_data.decrypt(&overview_key);

        assert_eq!(overview, DEMO_OVERVIEW_DECRYPTED.as_bytes());
    }
}
