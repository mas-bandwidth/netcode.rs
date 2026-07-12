/*
    netcode

    Copyright © 2017 - 2026, Más Bandwidth LLC

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

//! **netcode** is a secure client/server protocol for multiplayer games built on top of UDP.
//!
//! This crate is a Rust implementation of the [netcode 1.02 standard]. It interoperates with
//! the [reference C implementation] and other conforming implementations.
//!
//! [netcode 1.02 standard]: https://github.com/mas-bandwidth/netcode/blob/main/STANDARD.md
//! [reference C implementation]: https://github.com/mas-bandwidth/netcode
//!
//! # Overview
//!
//! A web backend authenticates each client and hands it a [connect token] over HTTPS. The client
//! uses the connect token to establish a connection with a dedicated server over UDP. Once
//! connected, the client and server exchange encrypted and signed packets.
//!
//! [connect token]: generate_connect_token
//!
//! # Example
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! let private_key = netcode::generate_key();
//! let protocol_id = 0x1122334455667788;
//!
//! let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
//! let mut server = netcode::Server::new(server_address, protocol_id, &private_key, 0.0).unwrap();
//! server.start(16).unwrap();
//!
//! let client_address: SocketAddr = "0.0.0.0:0".parse().unwrap();
//! let mut client = netcode::Client::new(client_address, 0.0).unwrap();
//!
//! let client_id = 1234;
//! let user_data = [0u8; netcode::USER_DATA_BYTES];
//! let connect_token = netcode::generate_connect_token(
//!     &[server_address],
//!     &[server_address],
//!     30,
//!     5,
//!     client_id,
//!     protocol_id,
//!     &private_key,
//!     &user_data,
//! )
//! .unwrap();
//!
//! client.connect(&connect_token).unwrap();
//!
//! let mut time = 0.0;
//! loop {
//!     client.update(time);
//!     server.update(time);
//!     if client.state() == netcode::ClientState::Connected {
//!         client.send_packet(&[1, 2, 3, 4]).unwrap();
//!     }
//!     while let Some((payload, _sequence)) = server.receive_packet(0) {
//!         println!("server received {} byte packet", payload.len());
//!     }
//!     std::thread::sleep(std::time::Duration::from_secs_f64(1.0 / 60.0));
//!     time += 1.0 / 60.0;
//! }
//! ```

mod bytes;
mod client;
mod crypto;
mod error;
mod packet;
mod replay;
mod server;
mod socket;
mod token;

pub use client::{Client, ClientState};
pub use crypto::generate_key;
pub use error::Error;
pub use server::{DisconnectReason, Server, ServerEvent};
pub use token::generate_connect_token;

/// The size of a connect token in bytes.
pub const CONNECT_TOKEN_BYTES: usize = 2048;

/// The size of an encryption key in bytes.
pub const KEY_BYTES: usize = 32;

/// The size of an AEAD authentication tag (HMAC) in bytes.
pub const MAC_BYTES: usize = 16;

/// The size of the per-client user data block carried in connect tokens.
pub const USER_DATA_BYTES: usize = 256;

/// The maximum number of server addresses in a connect token.
pub const MAX_SERVERS_PER_CONNECT: usize = 32;

/// The maximum number of client slots on a server.
pub const MAX_CLIENTS: usize = 256;

/// The maximum size of a payload packet in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 1200;

/// A 256-bit encryption key.
pub type Key = [u8; KEY_BYTES];

/// User data carried from the connect token to the server, opaque to netcode.
pub type UserData = [u8; USER_DATA_BYTES];

pub(crate) const VERSION_INFO: [u8; 13] = *b"NETCODE 1.02\0";
pub(crate) const MAX_PACKET_BYTES: usize = 1300;
pub(crate) const PACKET_SEND_RATE: f64 = 10.0;
pub(crate) const NUM_DISCONNECT_PACKETS: usize = 10;
pub(crate) const PACKET_QUEUE_SIZE: usize = 256;
