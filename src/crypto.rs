//! AEAD encryption primitives.
//!
//! Packets and challenge tokens are encrypted with ChaCha20-Poly1305 (IETF, 96-bit nonce).
//! Private connect token data is encrypted with XChaCha20-Poly1305 (IETF, 192-bit nonce).
//!
//! In both cases the buffer layout is the message followed by a 16-byte authentication
//! tag, matching the libsodium combined mode used by the reference implementation.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag, XChaCha20Poly1305};

use crate::{Error, Key, MAC_BYTES};

pub(crate) const NONCE_BYTES: usize = 12;
pub(crate) const XNONCE_BYTES: usize = 24;

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
}
