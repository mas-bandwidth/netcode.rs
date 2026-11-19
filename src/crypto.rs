//! AEAD encryption and key derivation primitives.
//!
//! Packets and challenge tokens are encrypted with ChaCha20-Poly1305 (IETF, 96-bit nonce).
//! Per-connection packet keys are derived from the connect token keys via HChaCha20 over
//! `client_salt || server_nonce`. Private connect token data is encrypted with
//! XChaCha20-Poly1305 (IETF, 192-bit nonce).
//!
//! In both AEAD modes the buffer layout is the message followed by a 16-byte authentication
//! tag, matching the libsodium combined mode used by the reference implementation.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag, XChaCha20Poly1305};
use zeroize::Zeroize;

use crate::{CONNECT_SALT_BYTES, Error, KEY_BYTES, Key, MAC_BYTES, SERVER_NONCE_BYTES};

pub(crate) const NONCE_BYTES: usize = 12;
pub(crate) const XNONCE_BYTES: usize = 24;

#[cfg(test)]
#[derive(Default)]
struct NonceAudit {
    seen: std::collections::HashSet<(Key, [u8; NONCE_BYTES])>,
    num_pairs: usize,
    repeats: usize,
}

#[cfg(test)]
std::thread_local! {
    static NONCE_AUDIT: std::cell::RefCell<Option<NonceAudit>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct NonceAuditScope;

#[cfg(test)]
impl NonceAuditScope {
    pub(crate) fn new() -> Self {
        NONCE_AUDIT.with(|cell| {
            *cell.borrow_mut() = Some(NonceAudit::default());
        });
        Self
    }

    pub(crate) fn num_pairs(&self) -> usize {
        NONCE_AUDIT.with(|cell| cell.borrow().as_ref().map_or(0, |a| a.num_pairs))
    }

    pub(crate) fn repeats(&self) -> usize {
        NONCE_AUDIT.with(|cell| cell.borrow().as_ref().map_or(0, |a| a.repeats))
    }
}

#[cfg(test)]
impl Drop for NonceAuditScope {
    fn drop(&mut self) {
        NONCE_AUDIT.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
fn record_nonce_audit(key: &Key, nonce: &[u8; NONCE_BYTES]) {
    NONCE_AUDIT.with(|cell| {
        if let Some(audit) = cell.borrow_mut().as_mut() {
            audit.num_pairs += 1;
            if !audit.seen.insert((*key, *nonce)) {
                audit.repeats += 1;
            }
        }
    });
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Constant-time HChaCha20 (`crypto_core_hchacha20(out, input, key, NULL)`).
pub(crate) fn hchacha20(key: &Key, input: &[u8; 16]) -> Key {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(input[i * 4..i * 4 + 4].try_into().unwrap());
    }

    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; KEY_BYTES];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    for i in 0..4 {
        out[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }

    state.zeroize();
    out
}

/// Derives a 32-byte per-connection packet key from a connect token key, `client_salt`,
/// and `server_nonce` via HChaCha20 over `client_salt || server_nonce`.
pub(crate) fn derive_packet_key(
    token_key: &Key,
    client_salt: &[u8; CONNECT_SALT_BYTES],
    server_nonce: &[u8; SERVER_NONCE_BYTES],
) -> Key {
    let mut input = [0u8; CONNECT_SALT_BYTES + SERVER_NONCE_BYTES];
    input[..CONNECT_SALT_BYTES].copy_from_slice(client_salt);
    input[CONNECT_SALT_BYTES..].copy_from_slice(server_nonce);
    let derived = hchacha20(token_key, &input);
    input.zeroize();
    derived
}

/// Constant-time 8-byte equality check for salts and nonces.
pub(crate) fn bytes_equal_8(a: &[u8; 8], b: &[u8; 8]) -> bool {
    let mut diff = 0u8;
    for i in 0..8 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// The 96-bit nonce for packet and challenge token encryption: four zero bytes
/// followed by the sequence number as a 64-bit little-endian value.
pub(crate) fn sequence_nonce(sequence: u64) -> [u8; NONCE_BYTES] {
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[4..].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

/// Encrypts `buffer[..len-16]` in place and writes the authentication tag to the last
/// 16 bytes of the buffer.
pub(crate) fn encrypt_aead(
    buffer: &mut [u8],
    additional_data: &[u8],
    nonce: &[u8; NONCE_BYTES],
    key: &Key,
) -> Result<(), Error> {
    #[cfg(test)]
    record_nonce_audit(key, nonce);

    let (message, mac) = buffer.split_last_chunk_mut::<MAC_BYTES>().ok_or(Error::EncryptFailed)?;
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(nonce.into(), additional_data, message.into())
        .map_err(|_| Error::EncryptFailed)?;
    mac.copy_from_slice(&tag);
    Ok(())
}

/// Decrypts `buffer[..len-16]` in place, authenticating against the tag in the last
/// 16 bytes of the buffer. The tag bytes are left untouched.
pub(crate) fn decrypt_aead(
    buffer: &mut [u8],
    additional_data: &[u8],
    nonce: &[u8; NONCE_BYTES],
    key: &Key,
) -> Result<(), Error> {
    let (message, mac) = buffer.split_last_chunk_mut::<MAC_BYTES>().ok_or(Error::DecryptFailed)?;
    ChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(nonce.into(), additional_data, message.into(), &Tag::from(*mac))
        .map_err(|_| Error::DecryptFailed)
}

/// XChaCha20-Poly1305 variant of [`encrypt_aead`], used for private connect token data.
pub(crate) fn encrypt_aead_big_nonce(
    buffer: &mut [u8],
    additional_data: &[u8],
    nonce: &[u8; XNONCE_BYTES],
    key: &Key,
) -> Result<(), Error> {
    let (message, mac) = buffer.split_last_chunk_mut::<MAC_BYTES>().ok_or(Error::EncryptFailed)?;
    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(nonce.into(), additional_data, message.into())
        .map_err(|_| Error::EncryptFailed)?;
    mac.copy_from_slice(&tag);
    Ok(())
}

/// XChaCha20-Poly1305 variant of [`decrypt_aead`], used for private connect token data.
pub(crate) fn decrypt_aead_big_nonce(
    buffer: &mut [u8],
    additional_data: &[u8],
    nonce: &[u8; XNONCE_BYTES],
    key: &Key,
) -> Result<(), Error> {
    let (message, mac) = buffer.split_last_chunk_mut::<MAC_BYTES>().ok_or(Error::DecryptFailed)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(nonce.into(), additional_data, message.into(), &Tag::from(*mac))
        .map_err(|_| Error::DecryptFailed)
}

pub(crate) fn random_bytes(buffer: &mut [u8]) {
    getrandom::fill(buffer).expect("the operating system random number generator failed");
}

/// Generates a cryptographically secure random 256-bit key.
pub fn generate_key() -> Key {
    let mut key = [0u8; crate::KEY_BYTES];
    random_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_round_trip() {
        let key = generate_key();
        let nonce = sequence_nonce(1000);
        let additional_data = b"additional data";

        let mut buffer = [0u8; 32 + MAC_BYTES];
        buffer[..32].copy_from_slice(&[0x42; 32]);

        encrypt_aead(&mut buffer, additional_data, &nonce, &key).unwrap();
        assert_ne!(&buffer[..32], &[0x42; 32]);

        decrypt_aead(&mut buffer, additional_data, &nonce, &key).unwrap();
        assert_eq!(&buffer[..32], &[0x42; 32]);
    }

    #[test]
    fn aead_rejects_tampering() {
        let key = generate_key();
        let nonce = sequence_nonce(1);

        let mut buffer = [0u8; 32 + MAC_BYTES];
        encrypt_aead(&mut buffer, &[], &nonce, &key).unwrap();

        buffer[0] ^= 1;
        assert!(matches!(decrypt_aead(&mut buffer, &[], &nonce, &key), Err(Error::DecryptFailed)));
    }

    #[test]
    fn aead_rejects_wrong_key() {
        let key = generate_key();
        let nonce = sequence_nonce(1);

        let mut buffer = [0u8; 32 + MAC_BYTES];
        encrypt_aead(&mut buffer, &[], &nonce, &key).unwrap();

        let wrong_key = generate_key();
        assert!(matches!(
            decrypt_aead(&mut buffer, &[], &nonce, &wrong_key),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn big_nonce_round_trip() {
        let key = generate_key();
        let mut nonce = [0u8; XNONCE_BYTES];
        random_bytes(&mut nonce);

        let mut buffer = [0u8; 64 + MAC_BYTES];
        buffer[..64].copy_from_slice(&[0x37; 64]);

        encrypt_aead_big_nonce(&mut buffer, b"aad", &nonce, &key).unwrap();
        decrypt_aead_big_nonce(&mut buffer, b"aad", &nonce, &key).unwrap();
        assert_eq!(&buffer[..64], &[0x37; 64]);
    }

    #[test]
    fn nonce_is_little_endian_sequence_in_high_bytes() {
        // [0 0 0 0][seq as 64-bit little-endian] -- getting this backwards produces
        // ciphertext incompatible with every other netcode implementation
        let nonce = sequence_nonce(0x1122334455667788);
        assert_eq!(nonce, [0, 0, 0, 0, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn test_derive_packet_keys_kat() {
        const DERIVED_C2S_KAT: Key = [
            0xa5, 0x22, 0x50, 0x53, 0xdd, 0xed, 0xab, 0xd2, 0xfd, 0xf7, 0x37, 0x92, 0x4c, 0x4e,
            0x7c, 0xda, 0x5c, 0x2f, 0x33, 0x4f, 0xe7, 0x89, 0x57, 0xb4, 0x99, 0xad, 0xf7, 0xe0,
            0xad, 0x14, 0x71, 0xdf,
        ];
        const DERIVED_S2C_KAT: Key = [
            0x8b, 0xe2, 0xca, 0xf2, 0x6f, 0x26, 0xa9, 0xbc, 0x17, 0x10, 0x17, 0x2d, 0xef, 0x25,
            0x0a, 0xd1, 0xb5, 0xbc, 0xf5, 0x43, 0x13, 0x8d, 0x75, 0x34, 0x99, 0x4a, 0xe6, 0x5d,
            0xdc, 0x25, 0xa6, 0xfb,
        ];

        let c2s_key: Key = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
        let s2c_key: Key = std::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(2));
        let client_salt: [u8; CONNECT_SALT_BYTES] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(21));
        let server_nonce: [u8; SERVER_NONCE_BYTES] =
            std::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(29));

        let derived_c2s = derive_packet_key(&c2s_key, &client_salt, &server_nonce);
        let derived_s2c = derive_packet_key(&s2c_key, &client_salt, &server_nonce);

        assert_eq!(derived_c2s, DERIVED_C2S_KAT);
        assert_eq!(derived_s2c, DERIVED_S2C_KAT);
        assert_ne!(derived_c2s, c2s_key);
        assert_ne!(derived_s2c, s2c_key);
        assert_ne!(derived_c2s, derived_s2c);

        let mut flipped_salt = client_salt;
        flipped_salt[0] ^= 1;
        assert_ne!(derive_packet_key(&c2s_key, &flipped_salt, &server_nonce), derived_c2s);

        let mut flipped_nonce = server_nonce;
        flipped_nonce[0] ^= 1;
        assert_ne!(derive_packet_key(&s2c_key, &client_salt, &flipped_nonce), derived_s2c);
    }
}
