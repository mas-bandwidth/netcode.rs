//! Entry points for the coverage-guided fuzz harnesses in `fuzz/`.
//!
//! This module is compiled only under `--cfg fuzzing`, which cargo-fuzz sets for the
//! entire build graph. It is not part of the crate's public API.
//!
//! Two kinds of harness, mirroring the reference C implementation's fuzz targets:
//! raw-bytes harnesses that assert the readers never panic on arbitrary input, and
//! write/read round-trip harnesses that assert anything the writers produce is
//! accepted and reproduced exactly by the readers.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::bytes::Reader;
use crate::packet::{self, AllowedPackets, Packet};
use crate::replay::ReplayProtection;
use crate::token::{
    self, CHALLENGE_TOKEN_BYTES, CONNECT_TOKEN_NONCE_BYTES, CONNECT_TOKEN_PRIVATE_BYTES,
    ConnectToken, PrivateConnectToken,
};
use crate::{
    CONNECT_TOKEN_BYTES, KEY_BYTES, Key, MAX_PACKET_BYTES, MAX_PAYLOAD_BYTES,
    MAX_SERVERS_PER_CONNECT, USER_DATA_BYTES,
};

const FUZZ_PROTOCOL_ID: u64 = 0x1122334455667788;

// fixed keys keep runs deterministic; the fuzzer controls the plaintext side anyway
const FUZZ_KEY: Key = [0x5A; KEY_BYTES];
const FUZZ_PRIVATE_KEY: Key = [0xA5; KEY_BYTES];

/// Feeds raw bytes to the packet reader as both a server and a client. Malformed and
/// unauthenticated packets must be ignored, never panic.
pub fn read_packet_raw(data: &[u8]) {
    let mut replay_protection = ReplayProtection::new();

    let mut buffer = data.to_vec();
    let _ = packet::read_packet(
        &mut buffer,
        Some(&FUZZ_KEY),
        FUZZ_PROTOCOL_ID,
        0,
        Some(&FUZZ_PRIVATE_KEY),
        AllowedPackets::SERVER,
        Some(&mut replay_protection),
    );

    let mut buffer = data.to_vec();
    let _ = packet::read_packet(
        &mut buffer,
        Some(&FUZZ_KEY),
        FUZZ_PROTOCOL_ID,
        0,
        None,
        AllowedPackets::CLIENT,
        Some(&mut replay_protection),
    );
}

/// Builds a packet of a fuzz-chosen type from the input, writes it, reads it back,
/// and asserts the round trip reproduces it exactly.
pub fn packet_write_read_round_trip(data: &[u8]) {
    if data.len() < 9 {
        return;
    }
    let selector = data[0];
    let sequence = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let rest = &data[9..];
    let mut reader = Reader::new(rest);

    let (packet, allowed_packets) = match selector % 7 {
        0 => (Packet::Denied, AllowedPackets::CLIENT),
        1 | 2 => {
            let Some(challenge_token_sequence) = reader.read_u64() else {
                return;
            };
            let Some(challenge_token_data) = reader.read_bytes::<CHALLENGE_TOKEN_BYTES>() else {
                return;
            };
            if selector % 7 == 1 {
                (
                    Packet::Challenge { challenge_token_sequence, challenge_token_data },
                    AllowedPackets::CLIENT,
                )
            } else {
                (
                    Packet::Response { challenge_token_sequence, challenge_token_data },
                    AllowedPackets::SERVER,
                )
            }
        }
        3 => {
            let Some(client_index) = reader.read_u32() else {
                return;
            };
            let Some(max_clients) = reader.read_u32() else {
                return;
            };
            (Packet::KeepAlive { client_index, max_clients }, AllowedPackets::CLIENT)
        }
        4 => {
            let payload = &rest[..rest.len().min(MAX_PAYLOAD_BYTES)];
            if payload.is_empty() {
                return;
            }
            (Packet::Payload(payload.to_vec()), AllowedPackets::CLIENT)
        }
        5 => (Packet::Disconnect, AllowedPackets::CLIENT),
        6 => return connection_request_round_trip(&mut reader),
        _ => unreachable!(),
    };

    let mut buffer = [0u8; MAX_PACKET_BYTES];
    let written = packet::write_packet(&packet, &mut buffer, sequence, &FUZZ_KEY, FUZZ_PROTOCOL_ID)
        .expect("write_packet must succeed for a valid packet");

    let (output, output_sequence) = packet::read_packet(
        &mut buffer[..written],
        Some(&FUZZ_KEY),
        FUZZ_PROTOCOL_ID,
        0,
        None,
        allowed_packets,
        None,
    )
    .expect("a packet produced by write_packet must read back");

    assert_eq!(output_sequence, sequence);
    assert_eq!(output, packet);
}

/// Builds a private connect token from the fuzz input, encrypts it into a connection
/// request packet, writes and reads the packet, and asserts the decrypted token
/// matches.
fn connection_request_round_trip(reader: &mut Reader<'_>) {
    let Some(client_id) = reader.read_u64() else {
        return;
    };
    let Some(timeout_raw) = reader.read_u32() else {
        return;
    };
    let Some(num_addresses_byte) = reader.read_u8() else {
        return;
    };
    let num_addresses = (num_addresses_byte as usize % MAX_SERVERS_PER_CONNECT) + 1;

    let mut server_addresses = Vec::with_capacity(num_addresses);
    for _ in 0..num_addresses {
        let Some(octets) = reader.read_bytes::<4>() else {
            return;
        };
        let Some(port) = reader.read_u16() else {
            return;
        };
        server_addresses.push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)));
    }

    let Some(client_to_server_key) = reader.read_bytes::<KEY_BYTES>() else {
        return;
    };
    let Some(server_to_client_key) = reader.read_bytes::<KEY_BYTES>() else {
        return;
    };
    let Some(user_data) = reader.read_bytes::<USER_DATA_BYTES>() else {
        return;
    };
    let Some(nonce) = reader.read_bytes::<CONNECT_TOKEN_NONCE_BYTES>() else {
        return;
    };
    let Some(expire_raw) = reader.read_u64() else {
        return;
    };
    // the reader rejects tokens whose expire timestamp is <= the current timestamp,
    // which the harness fixes at zero
    let expire_timestamp = expire_raw.max(1);

    let private_token = PrivateConnectToken {
        client_id,
        timeout_seconds: timeout_raw as i32,
        server_addresses,
        client_to_server_key,
        server_to_client_key,
        user_data,
    };

    let mut private_data = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
    private_token.write(&mut private_data);
    token::encrypt_connect_token_private(
        &mut private_data,
        FUZZ_PROTOCOL_ID,
        expire_timestamp,
        &nonce,
        &FUZZ_PRIVATE_KEY,
    )
    .expect("encrypting the private connect token must succeed");

    let request =
        Packet::Request { protocol_id: FUZZ_PROTOCOL_ID, expire_timestamp, nonce, private_data };

    let mut buffer = [0u8; MAX_PACKET_BYTES];
    let written = packet::write_packet(&request, &mut buffer, 0, &FUZZ_KEY, FUZZ_PROTOCOL_ID)
        .expect("write_packet must succeed for a valid connection request");

    let (output, _) = packet::read_packet(
        &mut buffer[..written],
        None,
        FUZZ_PROTOCOL_ID,
        0,
        Some(&FUZZ_PRIVATE_KEY),
        AllowedPackets::SERVER,
        None,
    )
    .expect("a connection request produced by write_packet must read back");

    let Packet::Request { private_data: decrypted, .. } = output else {
        panic!("connection request packet read back as a different type");
    };
    let output_token = PrivateConnectToken::read(&decrypted[..])
        .expect("the decrypted private connect token must read back");
    assert_eq!(output_token, private_token);
}

/// Parses arbitrary bytes as a public connect token. Anything that parses must
/// survive a write/read round trip unchanged.
pub fn connect_token_round_trip(data: &[u8]) {
    if data.len() < CONNECT_TOKEN_BYTES {
        return;
    }
    let buffer: [u8; CONNECT_TOKEN_BYTES] = data[..CONNECT_TOKEN_BYTES].try_into().unwrap();
    let Ok(token) = ConnectToken::read(&buffer) else {
        return;
    };

    let mut written = [0u8; CONNECT_TOKEN_BYTES];
    token.write(&mut written);
    let reread = ConnectToken::read(&written).expect("a written connect token must re-read");
    assert_eq!(reread, token);
}

/// Parses arbitrary bytes as a decrypted private connect token. Anything that parses
/// must survive a write/read round trip unchanged.
pub fn private_connect_token_round_trip(data: &[u8]) {
    if data.len() < CONNECT_TOKEN_PRIVATE_BYTES {
        return;
    }
    let Ok(token) = PrivateConnectToken::read(&data[..CONNECT_TOKEN_PRIVATE_BYTES]) else {
        return;
    };

    let mut written = [0u8; CONNECT_TOKEN_PRIVATE_BYTES];
    token.write(&mut written);
    let reread = PrivateConnectToken::read(&written[..])
        .expect("a written private connect token must re-read");
    assert_eq!(reread, token);
}
