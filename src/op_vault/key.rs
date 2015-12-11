use openssl::crypto::{hash, hmac, pkcs5, symm};

use op_vault::op_data_01::OpData01;

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

    pub fn from_op_data(key: &DerivedKey, op_data: &OpData01) -> Option<Self> {
        if let Some(plaintext) = op_data.decrypt_with_key(key) {
            let bytes = hash::hash(hash::Type::SHA512, &plaintext);
            let enc_key = bytes[0..32].to_vec();
            let mac_key = bytes[32..64].to_vec();
            Some(MainKey::new(enc_key, mac_key))
        } else {
            None
        }
    }

    pub fn from_op_data_str(key: &DerivedKey, b64str: &str) -> Option<Self> {
        OpData01::from_base64_str(b64str)
            .and_then(|op_data| MainKey::from_op_data(key, &op_data))
    }

    pub fn decrypt_op_data(&self, op_data: &OpData01) -> Option<Vec<u8>> {
        op_data.decrypt_with_key(self)
    }

    pub fn decrypt_op_data_str(&self, b64str: &str) -> Option<Vec<u8>> {
        OpData01::from_base64_str(b64str)
            .and_then(|op_data| op_data.decrypt_with_key(self))
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

#[cfg(test)]
mod tests {
    use base64;

    use op_vault::op_data_01::OpData01;

    const DEMO_PASSWORD: &'static str = "freddy";
    const DEMO_SALT: &'static str = "P0pOMMN6Ow5wIKOOSsaSQg==";
    const DEMO_ITERATIONS: usize = 50_000;
    const DEMO_OVERVIEW_KEY_OP_DATA: &'static str = "b3BkYXRhMDFAAAAAAAAAAIy1hZwIGeiLn4mLE1R8lEwIOye95GEyfZcPKlyXkkb0IBTfCXM+aDxjD7hOliuTM/YMIqxK+firVvW3c5cp2QMgvQHpDW2AsAQpBqcgBgRUCSP+THMVg15ZeR9lI77mHBpTQ70D+bchvkSmw3hoEGot7YcnQCATbouhMXIMO52D";
    const DEMO_OVERVIEW_OP_DATA: &'static str = "b3BkYXRhMDESAAAAAAAAAHw2J+nRQ2h7a9jZ8kH4ser/wKowBqgkJxv+RPujmrB7X53ooYk2wxyfiM2par2J44pCxLcNesV9F+jFCIecxGouN+3F033Ktzm3fKC2pGXy"; // from sample folder 379A3A7E5D5A47A6AA3A69C4D1E57D1B
    const DEMO_OVERVIEW: &'static str = r#"{"title":"Social"}"#;

    #[test]
    fn test_derived_key_validates_overview_key_op_data() {
        let salt = base64::u8de(DEMO_SALT.as_bytes()).unwrap();
        let derived_key = super::DerivedKey::from_password(&DEMO_PASSWORD, &salt, DEMO_ITERATIONS);
        let overview_key_op_data = OpData01::from_base64_str(DEMO_OVERVIEW_KEY_OP_DATA).unwrap();
        assert!(overview_key_op_data.validate_with_key(&derived_key));
    }

    #[test]
    fn test_overview_key_decrypts_overview() {
        let salt = base64::u8de(DEMO_SALT.as_bytes()).unwrap();
        let derived_key = super::DerivedKey::from_password(&DEMO_PASSWORD, &salt, DEMO_ITERATIONS);
        let overview_key = super::MainKey::from_op_data_str(&derived_key, DEMO_OVERVIEW_KEY_OP_DATA).unwrap();
        let overview = overview_key.decrypt_op_data_str(DEMO_OVERVIEW_OP_DATA).unwrap();
        assert_eq!(overview, DEMO_OVERVIEW.as_bytes());
    }
}
