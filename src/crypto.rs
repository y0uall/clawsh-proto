use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

use crate::error::ProtoError;
use crate::types::Psk;

type HmacSha256 = Hmac<Sha256>;

/// Minimum padded plaintext size before encryption.
/// All messages are padded to at least this size to prevent
/// message-size fingerprinting (e.g. heartbeats ~25-30B).
const MIN_PADDED_SIZE: usize = 256;

/// Ephemeral key pair for X25519 ECDH exchange.
pub struct KeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new ephemeral key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes for transmission.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform ECDH key exchange and derive a session key.
    /// Consumes the key pair (ephemeral secret is used once).
    pub fn derive_session_key(self, peer_public: &[u8; 32]) -> SessionKey {
        let peer_key = PublicKey::from(*peer_public);
        let shared_secret = self.secret.diffie_hellman(&peer_key);
        SessionKey::from_shared_secret(&shared_secret)
    }

    /// Perform ECDH key exchange and derive split encrypt/decrypt keys.
    /// Consumes the key pair (ephemeral secret is used once).
    /// Returns (encrypt_key, decrypt_key) for split ownership.
    pub fn derive_session_keys(self, peer_public: &[u8; 32]) -> (SessionEncryptKey, SessionDecryptKey) {
        let peer_key = PublicKey::from(*peer_public);
        let shared_secret = self.secret.diffie_hellman(&peer_key);

        let hk = Hkdf::<Sha256>::new(Some(b"clawsh-imp-session"), shared_secret.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"chacha20poly1305", &mut key)
            .expect("HKDF expand failed");

        let enc = SessionEncryptKey {
            key,
            nonce_counter: 0,
        };
        let dec = SessionDecryptKey { key };

        // Zeroize our copy
        key.zeroize();

        (enc, dec)
    }
}

/// Build a padded plaintext buffer: [4B real_len][plaintext][random_padding].
/// The total size is at least MIN_PADDED_SIZE bytes.
fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let real_len = plaintext.len() as u32;
    let inner_size = 4 + plaintext.len();
    let padded_size = inner_size.max(MIN_PADDED_SIZE);

    let mut buf = Vec::with_capacity(padded_size);
    buf.extend_from_slice(&real_len.to_be_bytes());
    buf.extend_from_slice(plaintext);

    // Fill remainder with random bytes
    if padded_size > inner_size {
        let pad_len = padded_size - inner_size;
        let mut padding = vec![0u8; pad_len];
        rand::thread_rng().fill_bytes(&mut padding);
        buf.extend_from_slice(&padding);
    }

    buf
}

/// Extract the real plaintext from a padded buffer.
fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if padded.len() < 4 {
        return Err(ProtoError::Crypto("padded plaintext too short".into()));
    }
    let real_len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if 4 + real_len > padded.len() {
        return Err(ProtoError::Crypto("invalid padded length".into()));
    }
    Ok(padded[4..4 + real_len].to_vec())
}

/// Derived session key for message-level encryption (ChaCha20-Poly1305).
/// Defense-in-depth: even if TLS is MitM'd, messages remain encrypted.
pub struct SessionKey {
    key: [u8; 32],
    nonce_counter: u64,
}

impl SessionKey {
    fn from_shared_secret(shared: &SharedSecret) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"clawsh-imp-session"), shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"chacha20poly1305", &mut key)
            .expect("HKDF expand failed");
        Self {
            key,
            nonce_counter: 0,
        }
    }

    /// Encrypt a plaintext message with padding. Returns ciphertext with nonce prepended.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        let padded = pad_plaintext(plaintext);
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, padded.as_ref())
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a ciphertext message and remove padding. Expects nonce prepended.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ProtoError> {
        if data.len() < 12 {
            return Err(ProtoError::Crypto("ciphertext too short".into()));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let padded = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        unpad_plaintext(&padded)
    }

    /// Generate next nonce from counter (monotonically increasing).
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        nonce
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce_counter = 0;
    }
}

/// Encryption half of a session key. Owns the nonce counter.
/// Designed for the writer side — no Mutex needed.
pub struct SessionEncryptKey {
    key: [u8; 32],
    nonce_counter: u64,
}

impl SessionEncryptKey {
    /// Encrypt a plaintext message with padding. Returns nonce-prepended ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        let padded = pad_plaintext(plaintext);
        let nonce_bytes = self.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, padded.as_ref())
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        nonce
    }
}

impl Drop for SessionEncryptKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce_counter = 0;
    }
}

/// Decryption half of a session key. Stateless (nonce comes from ciphertext).
/// Designed for the reader side — no Mutex needed.
pub struct SessionDecryptKey {
    key: [u8; 32],
}

impl SessionDecryptKey {
    /// Decrypt a ciphertext message and remove padding. Expects nonce prepended.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ProtoError> {
        if data.len() < 12 {
            return Err(ProtoError::Crypto("ciphertext too short".into()));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let padded = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| ProtoError::Crypto(e.to_string()))?;

        unpad_plaintext(&padded)
    }
}

impl Drop for SessionDecryptKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Compute HMAC-SHA256 for handshake authentication.
pub fn compute_auth_hmac(data: &[u8], psk: &Psk) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&psk.0)
        .expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Verify HMAC-SHA256 for handshake authentication.
pub fn verify_auth_hmac(data: &[u8], expected: &[u8; 32], psk: &Psk) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&psk.0)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip() {
        let psk = Psk::from_passphrase("test-key");
        let data = b"hello agent";
        let hmac = compute_auth_hmac(data, &psk);
        assert!(verify_auth_hmac(data, &hmac, &psk));
    }

    #[test]
    fn hmac_rejects_wrong_key() {
        let psk1 = Psk::from_passphrase("key-1");
        let psk2 = Psk::from_passphrase("key-2");
        let data = b"hello agent";
        let hmac = compute_auth_hmac(data, &psk1);
        assert!(!verify_auth_hmac(data, &hmac, &psk2));
    }

    #[test]
    fn session_key_encrypt_decrypt() {
        // Simulate key exchange between two parties
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let mut agent_session = agent_kp.derive_session_key(&handler_pub);
        let handler_session = handler_kp.derive_session_key(&agent_pub);

        let plaintext = b"sensitive recon data";
        let encrypted = agent_session.encrypt(plaintext).unwrap();
        let decrypted = handler_session.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn split_keys_encrypt_decrypt() {
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let (mut agent_enc, agent_dec) = agent_kp.derive_session_keys(&handler_pub);
        let (mut handler_enc, handler_dec) = handler_kp.derive_session_keys(&agent_pub);

        // Agent encrypts, handler decrypts
        let plaintext = b"recon data from agent";
        let encrypted = agent_enc.encrypt(plaintext).unwrap();
        let decrypted = handler_dec.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Handler encrypts, agent decrypts
        let plaintext2 = b"task from handler";
        let encrypted2 = handler_enc.encrypt(plaintext2).unwrap();
        let decrypted2 = agent_dec.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn split_keys_wrong_key_rejects() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let kp3 = KeyPair::generate();

        let pub2 = kp2.public_bytes();

        let (mut enc_1_2, _) = kp1.derive_session_keys(&pub2);
        let (_, dec_3_2) = kp3.derive_session_keys(&pub2);

        let encrypted = enc_1_2.encrypt(b"secret").unwrap();
        assert!(dec_3_2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn padding_roundtrip() {
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let (mut agent_enc, _) = agent_kp.derive_session_keys(&handler_pub);
        let (_, handler_dec) = handler_kp.derive_session_keys(&agent_pub);

        let plaintext = b"short msg";
        let encrypted = agent_enc.encrypt(plaintext).unwrap();
        let decrypted = handler_dec.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn padding_minimum_size() {
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let (mut agent_enc, _) = agent_kp.derive_session_keys(&handler_pub);
        let _ = handler_kp.derive_session_keys(&agent_pub);

        // 1 byte plaintext should still produce ciphertext >= MIN_PADDED_SIZE + 12 (nonce) + 16 (tag)
        let encrypted = agent_enc.encrypt(b"x").unwrap();
        // nonce(12) + encrypted(MIN_PADDED_SIZE + 16 tag)
        assert!(encrypted.len() >= 12 + MIN_PADDED_SIZE + 16);
    }

    #[test]
    fn padding_one_byte_plaintext() {
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let (mut enc, _) = agent_kp.derive_session_keys(&handler_pub);
        let (_, dec) = handler_kp.derive_session_keys(&agent_pub);

        let encrypted = enc.encrypt(b"A").unwrap();
        let decrypted = dec.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"A");
    }

    #[test]
    fn padding_large_plaintext() {
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let (mut enc, _) = agent_kp.derive_session_keys(&handler_pub);
        let (_, dec) = handler_kp.derive_session_keys(&agent_pub);

        // Plaintext larger than MIN_PADDED_SIZE should round-trip correctly
        let large = vec![0x42u8; 1024];
        let encrypted = enc.encrypt(&large).unwrap();
        let decrypted = dec.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, large);
    }

    #[test]
    fn session_key_padding_roundtrip() {
        let agent_kp = KeyPair::generate();
        let handler_kp = KeyPair::generate();

        let agent_pub = agent_kp.public_bytes();
        let handler_pub = handler_kp.public_bytes();

        let mut agent_session = agent_kp.derive_session_key(&handler_pub);
        let handler_session = handler_kp.derive_session_key(&agent_pub);

        // Verify SessionKey (legacy) also supports padding
        let plaintext = b"padded legacy message";
        let encrypted = agent_session.encrypt(plaintext).unwrap();
        let decrypted = handler_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
