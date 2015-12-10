use openssl::crypto::{hash, hmac, pkcs5, symm};

pub trait Key {
    fn enc_key(&self) -> &[u8];
    fn mac_key(&self) -> &[u8];

    fn compute_mac(&self, op_data: &[u8]) -> Vec<u8> {
        assert!(op_data.len() > 32); // TODO: make more bigger
        let content_end = op_data.len().saturating_sub(32);
        let content = &op_data[0..content_end];
        hmac::hmac(hash::Type::SHA256, self.mac_key(), content)
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

    pub fn from_encrypted_data(key: &DerivedKey, op_data: &[u8]) -> Self {
        let iv = &op_data[16..32];
        let content_end = op_data.len().saturating_sub(32);
        let content = &op_data[32..content_end];

        let crypter = symm::Crypter::new(symm::Type::AES_256_CBC);
        crypter.init(symm::Mode::Decrypt, key.enc_key(), iv);
        crypter.pad(false);

        let mut decrypted = crypter.update(content);
        decrypted.extend(crypter.finalize());
        decrypted = decrypted[16..].to_vec();

        let bytes = hash::hash(hash::Type::SHA512, &decrypted);
        let enc_key = bytes[0..32].to_vec();
        let mac_key = bytes[32..64].to_vec();

        MainKey::new(enc_key, mac_key)
    }

    fn decrypt(&self, op_data: &[u8]) -> Vec<u8> {
        let plaintext_len = u64_from_bytes_le(&op_data[8..16]) as usize;
        let iv = &op_data[16..32];
        let content_end = op_data.len().saturating_sub(32);
        let content = &op_data[32..content_end];

        let crypter = symm::Crypter::new(symm::Type::AES_256_CBC);
        crypter.init(symm::Mode::Decrypt, self.enc_key(), iv);
        crypter.pad(false);

        let mut decrypted = crypter.update(content);
        decrypted.extend(crypter.finalize());
        decrypted = decrypted[decrypted.len().saturating_sub(plaintext_len)..].to_vec();
        decrypted
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
    fn test_compute_mac() {
        let salt = base64::u8de(DEMO_SALT.as_bytes()).unwrap();
        let derived_key = super::DerivedKey::from_password(&DEMO_PASSWORD, &salt, DEMO_ITERATIONS);
        let op_data = base64::u8de(DEMO_OVERVIEW_KEY.as_bytes()).unwrap();
        let op_data_mac = &op_data[op_data.len().saturating_sub(32)..];
        assert_eq!(derived_key.compute_mac(&op_data), op_data_mac);
    }

    #[test]
    fn test_decrypt() {
        let salt = base64::u8de(DEMO_SALT.as_bytes()).unwrap();
        let derived_key = super::DerivedKey::from_password(&DEMO_PASSWORD, &salt, DEMO_ITERATIONS);
        let op_data = base64::u8de(DEMO_OVERVIEW_KEY.as_bytes()).unwrap();
        let overview_key = super::MainKey::from_encrypted_data(&derived_key, &op_data);
        let overview_op_data = base64::u8de(DEMO_OVERVIEW.as_bytes()).unwrap();
        let overview_op_data_mac = &overview_op_data[overview_op_data.len().saturating_sub(32)..];
        assert_eq!(overview_key.compute_mac(&overview_op_data), overview_op_data_mac);
        let overview_decrypted = overview_key.decrypt(&overview_op_data);
        assert_eq!(overview_decrypted, DEMO_OVERVIEW_DECRYPTED.as_bytes());
    }
}
