//! Packet reading and writing.
//!
//! The connection request packet travels in the clear (its private connect token data
//! is already encrypted by the backend). Every other packet type is encrypted with
//! ChaCha20-Poly1305, keyed per direction from the connect token, with the packet
//! sequence number as the nonce and the version info, protocol id and prefix byte as
//! associated data.

use log::debug;

use crate::bytes::{Reader, Writer};
use crate::crypto;
use crate::replay::ReplayProtection;
use crate::token::{CHALLENGE_TOKEN_BYTES, CONNECT_TOKEN_NONCE_BYTES, CONNECT_TOKEN_PRIVATE_BYTES};
use crate::{Error, Key, MAC_BYTES, MAX_PAYLOAD_BYTES, VERSION_INFO};

pub(crate) const CONNECTION_REQUEST_PACKET: u8 = 0;
pub(crate) const CONNECTION_DENIED_PACKET: u8 = 1;
pub(crate) const CONNECTION_CHALLENGE_PACKET: u8 = 2;
pub(crate) const CONNECTION_RESPONSE_PACKET: u8 = 3;
pub(crate) const CONNECTION_KEEP_ALIVE_PACKET: u8 = 4;
pub(crate) const CONNECTION_PAYLOAD_PACKET: u8 = 5;
pub(crate) const CONNECTION_DISCONNECT_PACKET: u8 = 6;
const CONNECTION_NUM_PACKETS: u8 = 7;

const CONNECTION_REQUEST_PACKET_BYTES: usize =
    1 + 13 + 8 + 8 + CONNECT_TOKEN_NONCE_BYTES + CONNECT_TOKEN_PRIVATE_BYTES;

#[cfg_attr(fuzzing, derive(Debug, PartialEq))]
pub(crate) enum Packet {
    Request {
        protocol_id: u64,
        expire_timestamp: u64,
        nonce: [u8; CONNECT_TOKEN_NONCE_BYTES],
        /// The private connect token data. Decrypted on read (with the original HMAC
        /// left in the trailing 16 bytes for the server's used-token history),
        /// encrypted on write.
        private_data: Box<[u8; CONNECT_TOKEN_PRIVATE_BYTES]>,
    },
    Denied,
    Challenge {
        challenge_token_sequence: u64,
        challenge_token_data: [u8; CHALLENGE_TOKEN_BYTES],
    },
    Response {
        challenge_token_sequence: u64,
        challenge_token_data: [u8; CHALLENGE_TOKEN_BYTES],
    },
    KeepAlive {
        client_index: u32,
        max_clients: u32,
    },
    Payload(Vec<u8>),
    Disconnect,
}

impl Packet {
    pub fn packet_type(&self) -> u8 {
        match self {
            Packet::Request { .. } => CONNECTION_REQUEST_PACKET,
            Packet::Denied => CONNECTION_DENIED_PACKET,
            Packet::Challenge { .. } => CONNECTION_CHALLENGE_PACKET,
            Packet::Response { .. } => CONNECTION_RESPONSE_PACKET,
            Packet::KeepAlive { .. } => CONNECTION_KEEP_ALIVE_PACKET,
            Packet::Payload(_) => CONNECTION_PAYLOAD_PACKET,
            Packet::Disconnect => CONNECTION_DISCONNECT_PACKET,
        }
    }
}

/// The set of packet types a receiver is willing to process. The server ignores
/// challenge packets and the client ignores request and response packets.
#[derive(Clone, Copy)]
pub(crate) struct AllowedPackets(u8);

impl AllowedPackets {
    pub const CLIENT: Self = Self(
        1 << CONNECTION_DENIED_PACKET
            | 1 << CONNECTION_CHALLENGE_PACKET
            | 1 << CONNECTION_KEEP_ALIVE_PACKET
            | 1 << CONNECTION_PAYLOAD_PACKET
            | 1 << CONNECTION_DISCONNECT_PACKET,
    );

    pub const SERVER: Self = Self(
        1 << CONNECTION_REQUEST_PACKET
            | 1 << CONNECTION_RESPONSE_PACKET
            | 1 << CONNECTION_KEEP_ALIVE_PACKET
            | 1 << CONNECTION_PAYLOAD_PACKET
            | 1 << CONNECTION_DISCONNECT_PACKET,
    );

    fn allows(self, packet_type: u8) -> bool {
        self.0 & (1 << packet_type) != 0
    }
}

/// The number of bytes required to send a sequence number, in `[1,8]`, found by
/// omitting high zero bytes.
fn sequence_number_bytes_required(sequence: u64) -> usize {
    (8 - sequence.leading_zeros() as usize / 8).max(1)
}

/// The associated data for packet encryption: version info, protocol id and the prefix
/// byte, which stops an attacker from modifying the packet type.
fn packet_additional_data(protocol_id: u64, prefix_byte: u8) -> [u8; 13 + 8 + 1] {
    let mut additional_data = [0u8; 13 + 8 + 1];
    let mut writer = Writer::new(&mut additional_data);
    writer.write_bytes(&VERSION_INFO);
    writer.write_u64(protocol_id);
    writer.write_u8(prefix_byte);
    additional_data
}

/// Writes the packet to the buffer, encrypting it if it is not a connection request
/// packet, and returns the number of bytes written.
pub(crate) fn write_packet(
    packet: &Packet,
    buffer: &mut [u8],
    sequence: u64,
    write_packet_key: &Key,
    protocol_id: u64,
) -> Result<usize, Error> {
    if let Packet::Request { protocol_id, expire_timestamp, nonce, private_data } = packet {
        // connection request packet: not encrypted, first byte is zero
        let mut writer = Writer::new(buffer);
        writer.write_u8(CONNECTION_REQUEST_PACKET);
        writer.write_bytes(&VERSION_INFO);
        writer.write_u64(*protocol_id);
        writer.write_u64(*expire_timestamp);
        writer.write_bytes(&nonce[..]);
        writer.write_bytes(&private_data[..]);
        debug_assert_eq!(writer.position(), CONNECTION_REQUEST_PACKET_BYTES);
        return Ok(CONNECTION_REQUEST_PACKET_BYTES);
    }

    // *** encrypted packets ***

    // the prefix byte combines the packet type (low 4 bits) with the number of
    // sequence bytes (high 4 bits)

    let sequence_bytes = sequence_number_bytes_required(sequence);
    let prefix_byte = packet.packet_type() | (sequence_bytes << 4) as u8;

    let mut writer = Writer::new(buffer);
    writer.write_u8(prefix_byte);

    // the sequence number is written with its high zero bytes omitted, low byte first

    let sequence_le = sequence.to_le_bytes();
    writer.write_bytes(&sequence_le[..sequence_bytes]);

    let encrypted_start = writer.position();

    match packet {
        Packet::Request { .. } => unreachable!(),
        Packet::Denied | Packet::Disconnect => {}
        Packet::Challenge { challenge_token_sequence, challenge_token_data }
        | Packet::Response { challenge_token_sequence, challenge_token_data } => {
            writer.write_u64(*challenge_token_sequence);
            writer.write_bytes(&challenge_token_data[..]);
        }
        Packet::KeepAlive { client_index, max_clients } => {
            writer.write_u32(*client_index);
            writer.write_u32(*max_clients);
        }
        Packet::Payload(payload) => {
            debug_assert!(!payload.is_empty() && payload.len() <= MAX_PAYLOAD_BYTES);
            writer.write_bytes(payload);
        }
    }

    let encrypted_finish = writer.position();

    let additional_data = packet_additional_data(protocol_id, prefix_byte);
    let nonce = crypto::sequence_nonce(sequence);
    crypto::encrypt_aead(
        &mut buffer[encrypted_start..encrypted_finish + MAC_BYTES],
        &additional_data,
        &nonce,
        write_packet_key,
    )?;

    Ok(encrypted_finish + MAC_BYTES)
}

/// Reads and validates a packet, decrypting it in place if it is encrypted.
///
/// Returns the packet and its sequence number, or `None` if the packet should be
/// ignored for any reason. The checks run in the exact order the standard requires;
/// in particular the replay window is tested before decryption and advanced only
/// after a successful decrypt.
pub(crate) fn read_packet(
    buffer: &mut [u8],
    read_packet_key: Option<&Key>,
    protocol_id: u64,
    current_timestamp: u64,
    private_key: Option<&Key>,
    allowed_packets: AllowedPackets,
    replay_protection: Option<&mut ReplayProtection>,
) -> Option<(Packet, u64)> {
    if buffer.is_empty() {
        debug!("ignored packet. buffer length is less than 1");
        return None;
    }

    let prefix_byte = buffer[0];

    if prefix_byte == CONNECTION_REQUEST_PACKET {
        return read_connection_request_packet(
            buffer,
            protocol_id,
            current_timestamp,
            private_key,
            allowed_packets,
        )
        .map(|packet| (packet, 0));
    }

    // *** encrypted packets ***

    let Some(read_packet_key) = read_packet_key else {
        debug!("ignored encrypted packet. no read packet key for this address");
        return None;
    };

    if buffer.len() < 1 + 1 + MAC_BYTES {
        debug!(
            "ignored encrypted packet. packet is too small to be valid ({} bytes)",
            buffer.len()
        );
        return None;
    }

    let packet_type = prefix_byte & 0xF;

    if packet_type >= CONNECTION_NUM_PACKETS {
        debug!("ignored encrypted packet. packet type {packet_type} is invalid");
        return None;
    }

    if !allowed_packets.allows(packet_type) {
        debug!("ignored encrypted packet. packet type {packet_type} is not allowed");
        return None;
    }

    let sequence_bytes = (prefix_byte >> 4) as usize;

    if !(1..=8).contains(&sequence_bytes) {
        debug!("ignored encrypted packet. sequence bytes {sequence_bytes} is out of range [1,8]");
        return None;
    }

    if buffer.len() < 1 + sequence_bytes + MAC_BYTES {
        debug!("ignored encrypted packet. buffer is too small for sequence bytes + encryption mac");
        return None;
    }

    let mut sequence_le = [0u8; 8];
    sequence_le[..sequence_bytes].copy_from_slice(&buffer[1..1 + sequence_bytes]);
    let sequence = u64::from_le_bytes(sequence_le);

    // ignore the packet if it has already been received

    let replay_protected = packet_type >= CONNECTION_KEEP_ALIVE_PACKET;

    if replay_protected {
        if let Some(replay_protection) = replay_protection.as_deref() {
            if replay_protection.already_received(sequence) {
                debug!(
                    "ignored packet. sequence {sequence:016x} already received (replay protection)"
                );
                return None;
            }
        }
    }

    // decrypt the per-packet type data

    let additional_data = packet_additional_data(protocol_id, prefix_byte);
    let nonce = crypto::sequence_nonce(sequence);
    let encrypted = &mut buffer[1 + sequence_bytes..];

    if crypto::decrypt_aead(encrypted, &additional_data, &nonce, read_packet_key).is_err() {
        debug!("ignored encrypted packet. failed to decrypt");
        return None;
    }

    // the packet decrypted, so it is authentic: advance the replay window

    if replay_protected {
        if let Some(replay_protection) = replay_protection {
            replay_protection.advance_sequence(sequence);
        }
    }

    // process the per-packet type data that was just decrypted

    let decrypted = &encrypted[..encrypted.len() - MAC_BYTES];
    let mut reader = Reader::new(decrypted);

    let packet = match packet_type {
        CONNECTION_DENIED_PACKET => {
            if !decrypted.is_empty() {
                debug!("ignored connection denied packet. decrypted packet data is wrong size");
                return None;
            }
            Packet::Denied
        }

        CONNECTION_CHALLENGE_PACKET | CONNECTION_RESPONSE_PACKET => {
            if decrypted.len() != 8 + CHALLENGE_TOKEN_BYTES {
                debug!(
                    "ignored connection challenge/response packet. decrypted packet data is wrong size"
                );
                return None;
            }
            let challenge_token_sequence = reader.read_u64()?;
            let challenge_token_data = reader.read_bytes::<CHALLENGE_TOKEN_BYTES>()?;
            if packet_type == CONNECTION_CHALLENGE_PACKET {
                Packet::Challenge { challenge_token_sequence, challenge_token_data }
            } else {
                Packet::Response { challenge_token_sequence, challenge_token_data }
            }
        }

        CONNECTION_KEEP_ALIVE_PACKET => {
            if decrypted.len() != 8 {
                debug!("ignored connection keep alive packet. decrypted packet data is wrong size");
                return None;
            }
            Packet::KeepAlive { client_index: reader.read_u32()?, max_clients: reader.read_u32()? }
        }

        CONNECTION_PAYLOAD_PACKET => {
            if decrypted.is_empty() || decrypted.len() > MAX_PAYLOAD_BYTES {
                debug!("ignored connection payload packet. payload size is out of range");
                return None;
            }
            Packet::Payload(decrypted.to_vec())
        }

        CONNECTION_DISCONNECT_PACKET => {
            if !decrypted.is_empty() {
                debug!("ignored connection disconnect packet. decrypted packet data is wrong size");
                return None;
            }
            Packet::Disconnect
        }

        _ => unreachable!(),
    };

    Some((packet, sequence))
}

fn read_connection_request_packet(
    buffer: &mut [u8],
    protocol_id: u64,
    current_timestamp: u64,
    private_key: Option<&Key>,
    allowed_packets: AllowedPackets,
) -> Option<Packet> {
    if !allowed_packets.allows(CONNECTION_REQUEST_PACKET) {
        debug!("ignored connection request packet. packet type is not allowed");
        return None;
    }

    if buffer.len() != CONNECTION_REQUEST_PACKET_BYTES {
        debug!(
            "ignored connection request packet. bad packet length (expected {}, got {})",
            CONNECTION_REQUEST_PACKET_BYTES,
            buffer.len()
        );
        return None;
    }

    let Some(private_key) = private_key else {
        debug!("ignored connection request packet. no private key");
        return None;
    };

    let mut reader = Reader::new(&buffer[1..]);

    if reader.read_bytes::<13>()? != VERSION_INFO {
        debug!("ignored connection request packet. bad version info");
        return None;
    }

    let packet_protocol_id = reader.read_u64()?;
    if packet_protocol_id != protocol_id {
        debug!(
            "ignored connection request packet. wrong protocol id. expected {protocol_id:016x}, got {packet_protocol_id:016x}"
        );
        return None;
    }

    let expire_timestamp = reader.read_u64()?;
    if expire_timestamp <= current_timestamp {
        debug!("ignored connection request packet. connect token expired");
        return None;
    }

    let nonce = reader.read_bytes::<CONNECT_TOKEN_NONCE_BYTES>()?;

    let private_data_start = buffer.len() - CONNECT_TOKEN_PRIVATE_BYTES;
    let mut private_data = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
    private_data.copy_from_slice(&buffer[private_data_start..]);

    if crate::token::decrypt_connect_token_private(
        &mut private_data,
        protocol_id,
        expire_timestamp,
        &nonce,
        private_key,
    )
    .is_err()
    {
        debug!("ignored connection request packet. connect token failed to decrypt");
        return None;
    }

    Some(Packet::Request { protocol_id: packet_protocol_id, expire_timestamp, nonce, private_data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_PACKET_BYTES;
    use crate::generate_key;

    const TEST_PROTOCOL_ID: u64 = 0x1122334455667788;
    const TEST_SEQUENCE: u64 = 1000;

    #[test]
    fn sequence_bytes_required() {
        assert_eq!(sequence_number_bytes_required(0), 1);
        assert_eq!(sequence_number_bytes_required(0xFF), 1);
        assert_eq!(sequence_number_bytes_required(0x100), 2);
        assert_eq!(sequence_number_bytes_required(0x1000), 2);
        assert_eq!(sequence_number_bytes_required(0x100000), 3);
        assert_eq!(sequence_number_bytes_required(0x10000000), 4);
        assert_eq!(sequence_number_bytes_required(0x1000000000), 5);
        assert_eq!(sequence_number_bytes_required(0x100000000000), 6);
        assert_eq!(sequence_number_bytes_required(0x10000000000000), 7);
        assert_eq!(sequence_number_bytes_required(0x1000000000000000), 8);
        assert_eq!(sequence_number_bytes_required(u64::MAX), 8);
    }

    #[test]
    fn sequence_number_encoding() {
        // a sequence number of 1000 (0x3E8) takes two bytes, written low byte first
        let key = generate_key();
        let mut buffer = [0u8; MAX_PACKET_BYTES];
        write_packet(&Packet::Denied, &mut buffer, 1000, &key, TEST_PROTOCOL_ID).unwrap();
        assert_eq!(buffer[0], CONNECTION_DENIED_PACKET | (2 << 4));
        assert_eq!(buffer[1], 0xE8);
        assert_eq!(buffer[2], 0x03);
    }

    fn round_trip(packet: &Packet, allowed_packets: AllowedPackets) -> (Packet, u64) {
        let key = generate_key();
        let mut buffer = [0u8; MAX_PACKET_BYTES];
        let written =
            write_packet(packet, &mut buffer, TEST_SEQUENCE, &key, TEST_PROTOCOL_ID).unwrap();
        read_packet(
            &mut buffer[..written],
            Some(&key),
            TEST_PROTOCOL_ID,
            0,
            None,
            allowed_packets,
            None,
        )
        .expect("packet failed to read")
    }

    #[test]
    fn denied_packet_round_trip() {
        let (packet, sequence) = round_trip(&Packet::Denied, AllowedPackets::CLIENT);
        assert!(matches!(packet, Packet::Denied));
        assert_eq!(sequence, TEST_SEQUENCE);
    }

    #[test]
    fn challenge_packet_round_trip() {
        let mut challenge_token_data = [0u8; CHALLENGE_TOKEN_BYTES];
        crypto::random_bytes(&mut challenge_token_data);
        let input = Packet::Challenge { challenge_token_sequence: 7, challenge_token_data };
        let (packet, _) = round_trip(&input, AllowedPackets::CLIENT);
        match packet {
            Packet::Challenge { challenge_token_sequence, challenge_token_data: data } => {
                assert_eq!(challenge_token_sequence, 7);
                assert_eq!(data, challenge_token_data);
            }
            _ => panic!("wrong packet type"),
        }
    }

    #[test]
    fn response_packet_round_trip() {
        let mut challenge_token_data = [0u8; CHALLENGE_TOKEN_BYTES];
        crypto::random_bytes(&mut challenge_token_data);
        let input = Packet::Response { challenge_token_sequence: 9, challenge_token_data };
        let (packet, _) = round_trip(&input, AllowedPackets::SERVER);
        match packet {
            Packet::Response { challenge_token_sequence, challenge_token_data: data } => {
                assert_eq!(challenge_token_sequence, 9);
                assert_eq!(data, challenge_token_data);
            }
            _ => panic!("wrong packet type"),
        }
    }

    #[test]
    fn keep_alive_packet_round_trip() {
        let input = Packet::KeepAlive { client_index: 10, max_clients: 16 };
        let (packet, _) = round_trip(&input, AllowedPackets::CLIENT);
        match packet {
            Packet::KeepAlive { client_index, max_clients } => {
                assert_eq!(client_index, 10);
                assert_eq!(max_clients, 16);
            }
            _ => panic!("wrong packet type"),
        }
    }

    #[test]
    fn payload_packet_round_trip() {
        let payload: Vec<u8> = (0..MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();
        let (packet, _) = round_trip(&Packet::Payload(payload.clone()), AllowedPackets::CLIENT);
        match packet {
            Packet::Payload(data) => assert_eq!(data, payload),
            _ => panic!("wrong packet type"),
        }
    }

    #[test]
    fn disconnect_packet_round_trip() {
        let (packet, _) = round_trip(&Packet::Disconnect, AllowedPackets::CLIENT);
        assert!(matches!(packet, Packet::Disconnect));
    }

    #[test]
    fn connection_request_packet_round_trip() {
        let private_key = generate_key();
        let expire_timestamp = crate::token::unix_timestamp() + 30;

        let mut nonce = [0u8; CONNECT_TOKEN_NONCE_BYTES];
        crypto::random_bytes(&mut nonce);

        let private_token = crate::token::PrivateConnectToken::generate(
            0x1234,
            10,
            &["127.0.0.1:40000".parse().unwrap()],
            &[0u8; crate::USER_DATA_BYTES],
        );
        let mut private_data = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
        private_token.write(&mut private_data);
        crate::token::encrypt_connect_token_private(
            &mut private_data,
            TEST_PROTOCOL_ID,
            expire_timestamp,
            &nonce,
            &private_key,
        )
        .unwrap();

        let input = Packet::Request {
            protocol_id: TEST_PROTOCOL_ID,
            expire_timestamp,
            nonce,
            private_data,
        };

        let key = generate_key();
        let mut buffer = [0u8; MAX_PACKET_BYTES];
        let written = write_packet(&input, &mut buffer, 0, &key, TEST_PROTOCOL_ID).unwrap();
        assert_eq!(written, CONNECTION_REQUEST_PACKET_BYTES);

        let (packet, _) = read_packet(
            &mut buffer[..written],
            None,
            TEST_PROTOCOL_ID,
            crate::token::unix_timestamp(),
            Some(&private_key),
            AllowedPackets::SERVER,
            None,
        )
        .expect("connection request packet failed to read");

        match packet {
            Packet::Request { private_data, .. } => {
                let output = crate::token::PrivateConnectToken::read(&private_data[..]).unwrap();
                assert_eq!(output.client_id, 0x1234);
            }
            _ => panic!("wrong packet type"),
        }
    }

    #[test]
    fn client_rejects_request_and_response_packets() {
        let key = generate_key();
        let mut challenge_token_data = [0u8; CHALLENGE_TOKEN_BYTES];
        crypto::random_bytes(&mut challenge_token_data);
        let input = Packet::Response { challenge_token_sequence: 1, challenge_token_data };

        let mut buffer = [0u8; MAX_PACKET_BYTES];
        let written = write_packet(&input, &mut buffer, 1, &key, TEST_PROTOCOL_ID).unwrap();
        assert!(
            read_packet(
                &mut buffer[..written],
                Some(&key),
                TEST_PROTOCOL_ID,
                0,
                None,
                AllowedPackets::CLIENT,
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn tampered_packet_rejected() {
        let key = generate_key();
        let mut buffer = [0u8; MAX_PACKET_BYTES];
        let written =
            write_packet(&Packet::Payload(vec![1, 2, 3]), &mut buffer, 1, &key, TEST_PROTOCOL_ID)
                .unwrap();

        // flipping the packet type in the prefix byte changes the associated data
        buffer[0] = (buffer[0] & 0xF0) | CONNECTION_KEEP_ALIVE_PACKET;
        assert!(
            read_packet(
                &mut buffer[..written],
                Some(&key),
                TEST_PROTOCOL_ID,
                0,
                None,
                AllowedPackets::CLIENT,
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn replayed_packet_rejected() {
        let key = generate_key();
        let mut replay_protection = ReplayProtection::new();

        let mut buffer = [0u8; MAX_PACKET_BYTES];
        let written =
            write_packet(&Packet::Payload(vec![1, 2, 3]), &mut buffer, 100, &key, TEST_PROTOCOL_ID)
                .unwrap();

        let mut first = buffer;
        assert!(
            read_packet(
                &mut first[..written],
                Some(&key),
                TEST_PROTOCOL_ID,
                0,
                None,
                AllowedPackets::CLIENT,
                Some(&mut replay_protection),
            )
            .is_some()
        );

        // the identical packet is rejected the second time
        let mut second = buffer;
        assert!(
            read_packet(
                &mut second[..written],
                Some(&key),
                TEST_PROTOCOL_ID,
                0,
                None,
                AllowedPackets::CLIENT,
                Some(&mut replay_protection),
            )
            .is_none()
        );
    }
}
