//! Connect tokens and challenge tokens.
//!
//! A connect token ensures that only authenticated clients can connect to dedicated
//! servers. Its private portion is encrypted and signed with a private key shared
//! between the web backend and the dedicated servers. Challenge tokens stop clients
//! with spoofed packet source addresses from connecting.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bytes::{Reader, Writer};
use crate::crypto::{self, XNONCE_BYTES};
use crate::{
    CONNECT_TOKEN_BYTES, Error, KEY_BYTES, Key, MAX_SERVERS_PER_CONNECT, USER_DATA_BYTES, UserData,
    VERSION_INFO,
};

pub(crate) const CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;
pub(crate) const CONNECT_TOKEN_NONCE_BYTES: usize = XNONCE_BYTES;
pub(crate) const CHALLENGE_TOKEN_BYTES: usize = 300;

/// The associated data protecting the private connect token: version info, protocol id
/// and expire timestamp. These fields travel in the clear but cannot be modified
/// without failing the signature check.
fn connect_token_additional_data(protocol_id: u64, expire_timestamp: u64) -> [u8; 13 + 8 + 8] {
    let mut additional_data = [0u8; 13 + 8 + 8];
    let mut writer = Writer::new(&mut additional_data);
    writer.write_bytes(&VERSION_INFO);
    writer.write_u64(protocol_id);
    writer.write_u64(expire_timestamp);
    additional_data
}

// ----------------------------------------------------------------

/// The private portion of a connect token. Readable only by the web backend and the
/// dedicated servers that share the private key.
#[cfg_attr(fuzzing, derive(Debug, PartialEq))]
pub(crate) struct PrivateConnectToken {
    pub client_id: u64,
    pub timeout_seconds: i32,
    pub server_addresses: Vec<SocketAddr>,
    pub client_to_server_key: Key,
    pub server_to_client_key: Key,
    pub user_data: UserData,
}

impl PrivateConnectToken {
    pub fn generate(
        client_id: u64,
        timeout_seconds: i32,
        server_addresses: &[SocketAddr],
        user_data: &UserData,
    ) -> Self {
        debug_assert!(!server_addresses.is_empty());
        debug_assert!(server_addresses.len() <= MAX_SERVERS_PER_CONNECT);
        Self {
            client_id,
            timeout_seconds,
            server_addresses: server_addresses.to_vec(),
            client_to_server_key: crypto::generate_key(),
            server_to_client_key: crypto::generate_key(),
            user_data: *user_data,
        }
    }

    pub fn write(&self, buffer: &mut [u8; CONNECT_TOKEN_PRIVATE_BYTES]) {
        let mut writer = Writer::new(buffer);
        writer.write_u64(self.client_id);
        writer.write_u32(self.timeout_seconds as u32);
        writer.write_u32(self.server_addresses.len() as u32);
        for &address in &self.server_addresses {
            writer.write_address(address);
        }
        writer.write_bytes(&self.client_to_server_key);
        writer.write_bytes(&self.server_to_client_key);
        writer.write_bytes(&self.user_data);
        writer.zero_pad_to_end();
    }

    pub fn read(buffer: &[u8]) -> Result<Self, Error> {
        if buffer.len() < CONNECT_TOKEN_PRIVATE_BYTES {
            return Err(Error::InvalidConnectToken);
        }

        let mut reader = Reader::new(buffer);
        (|| {
            let client_id = reader.read_u64()?;
            let timeout_seconds = reader.read_u32()? as i32;

            let num_server_addresses = reader.read_u32()? as usize;
            if !(1..=MAX_SERVERS_PER_CONNECT).contains(&num_server_addresses) {
                return None;
            }

            let mut server_addresses = Vec::with_capacity(num_server_addresses);
            for _ in 0..num_server_addresses {
                server_addresses.push(reader.read_address()?);
            }

            Some(Self {
                client_id,
                timeout_seconds,
                server_addresses,
                client_to_server_key: reader.read_bytes::<KEY_BYTES>()?,
                server_to_client_key: reader.read_bytes::<KEY_BYTES>()?,
                user_data: reader.read_bytes::<USER_DATA_BYTES>()?,
            })
        })()
        .ok_or(Error::InvalidConnectToken)
    }
}

/// Encrypts the first 1008 bytes of the buffer in place, storing the HMAC in the last
/// 16 bytes.
pub(crate) fn encrypt_connect_token_private(
    buffer: &mut [u8; CONNECT_TOKEN_PRIVATE_BYTES],
    protocol_id: u64,
    expire_timestamp: u64,
    nonce: &[u8; CONNECT_TOKEN_NONCE_BYTES],
    key: &Key,
) -> Result<(), Error> {
    let additional_data = connect_token_additional_data(protocol_id, expire_timestamp);
    crypto::encrypt_aead_big_nonce(buffer, &additional_data, nonce, key)
}

/// Decrypts the buffer in place. The trailing 16 HMAC bytes are left untouched, so the
/// original token HMAC remains available for the server's used-token history.
pub(crate) fn decrypt_connect_token_private(
    buffer: &mut [u8; CONNECT_TOKEN_PRIVATE_BYTES],
    protocol_id: u64,
    expire_timestamp: u64,
    nonce: &[u8; CONNECT_TOKEN_NONCE_BYTES],
    key: &Key,
) -> Result<(), Error> {
    let additional_data = connect_token_additional_data(protocol_id, expire_timestamp);
    crypto::decrypt_aead_big_nonce(buffer, &additional_data, nonce, key)
}

// ----------------------------------------------------------------

pub(crate) struct ChallengeToken {
    pub client_id: u64,
    pub user_data: UserData,
}

impl ChallengeToken {
    pub fn write(&self, buffer: &mut [u8; CHALLENGE_TOKEN_BYTES]) {
        let mut writer = Writer::new(buffer);
        writer.write_u64(self.client_id);
        writer.write_bytes(&self.user_data);
        writer.zero_pad_to_end();
    }

    pub fn read(buffer: &[u8; CHALLENGE_TOKEN_BYTES]) -> Self {
        let mut reader = Reader::new(buffer);
        Self {
            client_id: reader.read_u64().unwrap(),
            user_data: reader.read_bytes::<USER_DATA_BYTES>().unwrap(),
        }
    }
}

/// Encrypts the first 284 bytes of the buffer in place using the challenge sequence
/// number as the nonce, storing the HMAC in the last 16 bytes.
pub(crate) fn encrypt_challenge_token(
    buffer: &mut [u8; CHALLENGE_TOKEN_BYTES],
    sequence: u64,
    key: &Key,
) -> Result<(), Error> {
    crypto::encrypt_aead(buffer, &[], &crypto::sequence_nonce(sequence), key)
}

pub(crate) fn decrypt_challenge_token(
    buffer: &mut [u8; CHALLENGE_TOKEN_BYTES],
    sequence: u64,
    key: &Key,
) -> Result<(), Error> {
    crypto::decrypt_aead(buffer, &[], &crypto::sequence_nonce(sequence), key)
}

// ----------------------------------------------------------------

/// A parsed connect token: the public fields the client needs to connect, wrapped
/// around the encrypted private data it forwards to the server.
#[cfg_attr(fuzzing, derive(Debug, PartialEq))]
pub(crate) struct ConnectToken {
    pub protocol_id: u64,
    pub create_timestamp: u64,
    pub expire_timestamp: u64,
    pub nonce: [u8; CONNECT_TOKEN_NONCE_BYTES],
    pub private_data: Box<[u8; CONNECT_TOKEN_PRIVATE_BYTES]>,
    pub timeout_seconds: i32,
    pub server_addresses: Vec<SocketAddr>,
    pub client_to_server_key: Key,
    pub server_to_client_key: Key,
}

impl ConnectToken {
    pub fn write(&self, buffer: &mut [u8; CONNECT_TOKEN_BYTES]) {
        let mut writer = Writer::new(buffer);
        writer.write_bytes(&VERSION_INFO);
        writer.write_u64(self.protocol_id);
        writer.write_u64(self.create_timestamp);
        writer.write_u64(self.expire_timestamp);
        writer.write_bytes(&self.nonce);
        writer.write_bytes(&self.private_data[..]);
        writer.write_u32(self.timeout_seconds as u32);
        writer.write_u32(self.server_addresses.len() as u32);
        for &address in &self.server_addresses {
            writer.write_address(address);
        }
        writer.write_bytes(&self.client_to_server_key);
        writer.write_bytes(&self.server_to_client_key);
        writer.zero_pad_to_end();
    }

    pub fn read(buffer: &[u8; CONNECT_TOKEN_BYTES]) -> Result<Self, Error> {
        let mut reader = Reader::new(buffer);
        (|| {
            if reader.read_bytes::<13>()? != VERSION_INFO {
                return None;
            }

            let protocol_id = reader.read_u64()?;
            let create_timestamp = reader.read_u64()?;
            let expire_timestamp = reader.read_u64()?;
            if create_timestamp > expire_timestamp {
                return None;
            }

            let nonce = reader.read_bytes::<CONNECT_TOKEN_NONCE_BYTES>()?;
            let private_data = Box::new(reader.read_bytes::<CONNECT_TOKEN_PRIVATE_BYTES>()?);
            let timeout_seconds = reader.read_u32()? as i32;

            let num_server_addresses = reader.read_u32()? as usize;
            if !(1..=MAX_SERVERS_PER_CONNECT).contains(&num_server_addresses) {
                return None;
            }

            let mut server_addresses = Vec::with_capacity(num_server_addresses);
            for _ in 0..num_server_addresses {
                server_addresses.push(reader.read_address()?);
            }

            Some(Self {
                protocol_id,
                create_timestamp,
                expire_timestamp,
                nonce,
                private_data,
                timeout_seconds,
                server_addresses,
                client_to_server_key: reader.read_bytes::<KEY_BYTES>()?,
                server_to_client_key: reader.read_bytes::<KEY_BYTES>()?,
            })
        })()
        .ok_or(Error::InvalidConnectToken)
    }
}

pub(crate) fn unix_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock is before 1970").as_secs()
}

/// Generates a connect token.
///
/// This is what the web backend calls to authorize a client. The returned buffer is
/// passed to the client over a secure channel (e.g. HTTPS), and the client passes it
/// to [`Client::connect`](crate::Client::connect).
///
/// `public_server_addresses` are the addresses the client connects to. The matching
/// entries in `internal_server_addresses` go inside the encrypted private token and
/// are what each server checks its own address against; they may differ from the
/// public addresses when servers sit behind NAT or a load balancer. Both slices must
/// have the same length, in the range `[1, MAX_SERVERS_PER_CONNECT]`.
///
/// The token expires `expire_seconds` after creation; negative means never expires
/// (dev only). `timeout_seconds` is how long a connection can go without receiving
/// packets before it is dropped; negative disables timeouts (dev only).
#[allow(clippy::too_many_arguments)]
pub fn generate_connect_token(
    public_server_addresses: &[SocketAddr],
    internal_server_addresses: &[SocketAddr],
    expire_seconds: i32,
    timeout_seconds: i32,
    client_id: u64,
    protocol_id: u64,
    private_key: &Key,
    user_data: &UserData,
) -> Result<[u8; CONNECT_TOKEN_BYTES], Error> {
    if public_server_addresses.is_empty()
        || public_server_addresses.len() > MAX_SERVERS_PER_CONNECT
        || public_server_addresses.len() != internal_server_addresses.len()
    {
        return Err(Error::InvalidServerAddresses);
    }

    let create_timestamp = unix_timestamp();
    let expire_timestamp =
        if expire_seconds >= 0 { create_timestamp + expire_seconds as u64 } else { u64::MAX };

    let mut nonce = [0u8; CONNECT_TOKEN_NONCE_BYTES];
    crypto::random_bytes(&mut nonce);

    let private_token = PrivateConnectToken::generate(
        client_id,
        timeout_seconds,
        internal_server_addresses,
        user_data,
    );

    let mut private_data = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
    private_token.write(&mut private_data);
    encrypt_connect_token_private(
        &mut private_data,
        protocol_id,
        expire_timestamp,
        &nonce,
        private_key,
    )?;

    let connect_token = ConnectToken {
        protocol_id,
        create_timestamp,
        expire_timestamp,
        nonce,
        private_data,
        timeout_seconds,
        server_addresses: public_server_addresses.to_vec(),
        client_to_server_key: private_token.client_to_server_key,
        server_to_client_key: private_token.server_to_client_key,
    };

    let mut buffer = [0u8; CONNECT_TOKEN_BYTES];
    connect_token.write(&mut buffer);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_key;

    const TEST_PROTOCOL_ID: u64 = 0x1122334455667788;

    fn test_user_data() -> UserData {
        let mut user_data = [0u8; USER_DATA_BYTES];
        crypto::random_bytes(&mut user_data);
        user_data
    }

    #[test]
    fn private_connect_token_round_trip() {
        let server_addresses: Vec<SocketAddr> =
            vec!["127.0.0.1:40000".parse().unwrap(), "[::1]:50000".parse().unwrap()];
        let user_data = test_user_data();
        let token = PrivateConnectToken::generate(0x1234, 10, &server_addresses, &user_data);

        let key = generate_key();
        let mut nonce = [0u8; CONNECT_TOKEN_NONCE_BYTES];
        crypto::random_bytes(&mut nonce);
        let expire_timestamp = unix_timestamp() + 30;

        let mut buffer = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
        token.write(&mut buffer);
        encrypt_connect_token_private(
            &mut buffer,
            TEST_PROTOCOL_ID,
            expire_timestamp,
            &nonce,
            &key,
        )
        .unwrap();
        decrypt_connect_token_private(
            &mut buffer,
            TEST_PROTOCOL_ID,
            expire_timestamp,
            &nonce,
            &key,
        )
        .unwrap();

        let output = PrivateConnectToken::read(&buffer[..]).unwrap();
        assert_eq!(output.client_id, token.client_id);
        assert_eq!(output.timeout_seconds, token.timeout_seconds);
        assert_eq!(output.server_addresses, token.server_addresses);
        assert_eq!(output.client_to_server_key, token.client_to_server_key);
        assert_eq!(output.server_to_client_key, token.server_to_client_key);
        assert_eq!(output.user_data, token.user_data);
    }

    #[test]
    fn private_connect_token_rejects_modified_associated_data() {
        let server_addresses: Vec<SocketAddr> = vec!["127.0.0.1:40000".parse().unwrap()];
        let user_data = test_user_data();
        let token = PrivateConnectToken::generate(0x1234, 10, &server_addresses, &user_data);

        let key = generate_key();
        let mut nonce = [0u8; CONNECT_TOKEN_NONCE_BYTES];
        crypto::random_bytes(&mut nonce);
        let expire_timestamp = unix_timestamp() + 30;

        let mut buffer = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
        token.write(&mut buffer);
        encrypt_connect_token_private(
            &mut buffer,
            TEST_PROTOCOL_ID,
            expire_timestamp,
            &nonce,
            &key,
        )
        .unwrap();

        // a different protocol id or expire timestamp must fail the signature check
        assert!(
            decrypt_connect_token_private(
                &mut buffer.clone(),
                TEST_PROTOCOL_ID + 1,
                expire_timestamp,
                &nonce,
                &key
            )
            .is_err()
        );
        assert!(
            decrypt_connect_token_private(
                &mut buffer.clone(),
                TEST_PROTOCOL_ID,
                expire_timestamp + 1,
                &nonce,
                &key
            )
            .is_err()
        );
    }

    #[test]
    fn challenge_token_round_trip() {
        let token = ChallengeToken { client_id: 0xDEADBEEF, user_data: test_user_data() };

        let key = generate_key();
        let sequence = 42;

        let mut buffer = [0u8; CHALLENGE_TOKEN_BYTES];
        token.write(&mut buffer);
        encrypt_challenge_token(&mut buffer, sequence, &key).unwrap();
        decrypt_challenge_token(&mut buffer, sequence, &key).unwrap();

        let output = ChallengeToken::read(&buffer);
        assert_eq!(output.client_id, token.client_id);
        assert_eq!(output.user_data, token.user_data);
    }

    #[test]
    fn connect_token_round_trip() {
        let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let private_key = generate_key();
        let user_data = test_user_data();

        let buffer = generate_connect_token(
            &[server_address],
            &[server_address],
            30,
            5,
            0x1234,
            TEST_PROTOCOL_ID,
            &private_key,
            &user_data,
        )
        .unwrap();

        let token = ConnectToken::read(&buffer).unwrap();
        assert_eq!(token.protocol_id, TEST_PROTOCOL_ID);
        assert_eq!(token.expire_timestamp, token.create_timestamp + 30);
        assert_eq!(token.timeout_seconds, 5);
        assert_eq!(token.server_addresses, vec![server_address]);

        // the private data decrypts with the private key and matches
        let mut private_data = token.private_data.clone();
        decrypt_connect_token_private(
            &mut private_data,
            TEST_PROTOCOL_ID,
            token.expire_timestamp,
            &token.nonce,
            &private_key,
        )
        .unwrap();
        let private_token = PrivateConnectToken::read(&private_data[..]).unwrap();
        assert_eq!(private_token.client_id, 0x1234);
        assert_eq!(private_token.timeout_seconds, 5);
        assert_eq!(private_token.server_addresses, vec![server_address]);
        assert_eq!(private_token.client_to_server_key, token.client_to_server_key);
        assert_eq!(private_token.server_to_client_key, token.server_to_client_key);
        assert_eq!(private_token.user_data, user_data);
    }

    #[test]
    fn connect_token_rejects_bad_version_info() {
        let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut buffer = generate_connect_token(
            &[server_address],
            &[server_address],
            30,
            5,
            1,
            TEST_PROTOCOL_ID,
            &generate_key(),
            &[0u8; USER_DATA_BYTES],
        )
        .unwrap();

        buffer[0] = b'X';
        assert!(ConnectToken::read(&buffer).is_err());
    }

    #[test]
    fn connect_token_rejects_create_after_expire() {
        let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut buffer = generate_connect_token(
            &[server_address],
            &[server_address],
            30,
            5,
            1,
            TEST_PROTOCOL_ID,
            &generate_key(),
            &[0u8; USER_DATA_BYTES],
        )
        .unwrap();

        // create timestamp lives at offset 21, expire at 29: swap them
        let create: [u8; 8] = buffer[21..29].try_into().unwrap();
        let expire: [u8; 8] = buffer[29..37].try_into().unwrap();
        buffer[21..29].copy_from_slice(&expire);
        buffer[29..37].copy_from_slice(&create);
        assert!(ConnectToken::read(&buffer).is_err());
    }
}
