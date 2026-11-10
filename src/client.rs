//! The netcode client.

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;

use log::{debug, info};
use zeroize::Zeroize;

use crate::packet::{AllowedPackets, Packet};
use crate::replay::ReplayProtection;
use crate::token::{self, CHALLENGE_TOKEN_BYTES, ConnectToken};
use crate::{
    CONNECT_TOKEN_BYTES, Error, KEY_BYTES, Key, MAX_CLIENTS, MAX_PACKET_BYTES, MAX_PAYLOAD_BYTES,
    NUM_DISCONNECT_PACKETS, PACKET_QUEUE_SIZE, PACKET_SEND_RATE, socket,
};

/// The state of a [`Client`].
///
/// The initial state is [`Disconnected`](ClientState::Disconnected); the goal state is
/// [`Connected`](ClientState::Connected). The [`is_error`](ClientState::is_error),
/// [`is_connecting`](ClientState::is_connecting) and
/// [`is_disconnected`](ClientState::is_disconnected) predicates classify the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// The connect token expired before the client finished connecting.
    ConnectTokenExpired,
    /// The connect token passed to [`Client::connect`] was invalid.
    InvalidConnectToken,
    /// The established connection timed out.
    ConnectionTimedOut,
    /// The server stopped responding while the client was sending connection responses.
    ConnectionResponseTimedOut,
    /// The server never responded to the client's connection requests.
    ConnectionRequestTimedOut,
    /// The server denied the connection (for example, because it was full).
    ConnectionDenied,
    /// Not connected. The initial state.
    Disconnected,
    /// Sending connection request packets to the server.
    SendingConnectionRequest,
    /// Sending connection response packets to the server.
    SendingConnectionResponse,
    /// Connected: payload packets can be exchanged with the server.
    Connected,
}

impl ClientState {
    /// Whether this is one of the error states.
    pub fn is_error(self) -> bool {
        matches!(
            self,
            ClientState::ConnectTokenExpired
                | ClientState::InvalidConnectToken
                | ClientState::ConnectionTimedOut
                | ClientState::ConnectionResponseTimedOut
                | ClientState::ConnectionRequestTimedOut
                | ClientState::ConnectionDenied
        )
    }

    /// Whether the client is partway through connecting: sending connection requests
    /// or connection responses.
    pub fn is_connecting(self) -> bool {
        matches!(
            self,
            ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse
        )
    }

    /// Whether the client is disconnected, either cleanly
    /// ([`Disconnected`](ClientState::Disconnected)) or in an error state.
    pub fn is_disconnected(self) -> bool {
        self == ClientState::Disconnected || self.is_error()
    }
}

impl fmt::Display for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ClientState::ConnectTokenExpired => "connect token expired",
            ClientState::InvalidConnectToken => "invalid connect token",
            ClientState::ConnectionTimedOut => "connection timed out",
            ClientState::ConnectionResponseTimedOut => "connection response timed out",
            ClientState::ConnectionRequestTimedOut => "connection request timed out",
            ClientState::ConnectionDenied => "connection denied",
            ClientState::Disconnected => "disconnected",
            ClientState::SendingConnectionRequest => "sending connection request",
            ClientState::SendingConnectionResponse => "sending connection response",
            ClientState::Connected => "connected",
        };
        f.write_str(name)
    }
}

/// A netcode client.
///
/// Drive it by calling [`update`](Client::update) once per frame with the current
/// time. All methods must be called from one thread; the client performs no internal
/// synchronization.
pub struct Client {
    state: ClientState,
    time: f64,
    connect_start_time: f64,
    last_packet_send_time: f64,
    last_packet_receive_time: f64,
    should_disconnect: Option<ClientState>,
    sequence: u64,
    client_index: usize,
    max_clients: usize,
    server_address_index: usize,
    server_address: Option<SocketAddr>,
    connect_token: Option<ConnectToken>,
    socket_ipv4: Option<socket::Transport>,
    socket_ipv6: Option<socket::Transport>,
    primary_is_ipv4: bool,
    write_packet_key: Key,
    read_packet_key: Key,
    replay_protection: ReplayProtection,
    packet_receive_queue: VecDeque<(Vec<u8>, u64)>,
    challenge_token_sequence: u64,
    challenge_token_data: [u8; CHALLENGE_TOKEN_BYTES],
}

impl Client {
    /// Creates a client with a socket bound to `bind_address`. Bind to port 0 to let
    /// the operating system pick a port.
    ///
    /// The client can only reach server addresses in the same address family as the
    /// bind address; use [`new_dual`](Client::new_dual) to support connect tokens
    /// that mix IPv4 and IPv6 server addresses.
    pub fn new(bind_address: SocketAddr, time: f64) -> Result<Self, Error> {
        match bind_address {
            SocketAddr::V4(_) => Self::create(Some(bind_address), None, true, time),
            SocketAddr::V6(_) => Self::create(None, Some(bind_address), false, time),
        }
    }

    /// Creates a client with one IPv4 socket and one IPv6 socket, so it can connect
    /// to server addresses of either family.
    pub fn new_dual(
        bind_address_ipv4: SocketAddr,
        bind_address_ipv6: SocketAddr,
        time: f64,
    ) -> Result<Self, Error> {
        if !bind_address_ipv4.is_ipv4() || !bind_address_ipv6.is_ipv6() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "new_dual requires one IPv4 and one IPv6 bind address",
            )));
        }
        Self::create(Some(bind_address_ipv4), Some(bind_address_ipv6), true, time)
    }

    #[cfg(test)]
    pub(crate) fn new_in_memory(
        network: &socket::MemoryNetwork,
        bind_address: SocketAddr,
        time: f64,
    ) -> Self {
        match bind_address {
            SocketAddr::V4(_) => Self::with_transports(
                Some(socket::Transport::Memory(network.bind(bind_address))),
                None,
                true,
                time,
            ),
            SocketAddr::V6(_) => Self::with_transports(
                None,
                Some(socket::Transport::Memory(network.bind(bind_address))),
                false,
                time,
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_dual_in_memory(
        network: &socket::MemoryNetwork,
        bind_address_ipv4: SocketAddr,
        bind_address_ipv6: SocketAddr,
        time: f64,
    ) -> Result<Self, Error> {
        if !bind_address_ipv4.is_ipv4() || !bind_address_ipv6.is_ipv6() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "new_dual requires one IPv4 and one IPv6 bind address",
            )));
        }
        Ok(Self::with_transports(
            Some(socket::Transport::Memory(network.bind(bind_address_ipv4))),
            Some(socket::Transport::Memory(network.bind(bind_address_ipv6))),
            true,
            time,
        ))
    }

    fn create(
        bind_address_ipv4: Option<SocketAddr>,
        bind_address_ipv6: Option<SocketAddr>,
        primary_is_ipv4: bool,
        time: f64,
    ) -> Result<Self, Error> {
        let socket_ipv4 = bind_address_ipv4.map(socket::create_socket).transpose()?;
        let socket_ipv6 = bind_address_ipv6.map(socket::create_socket).transpose()?;
        Ok(Self::with_transports(socket_ipv4, socket_ipv6, primary_is_ipv4, time))
    }

    fn with_transports(
        socket_ipv4: Option<socket::Transport>,
        socket_ipv6: Option<socket::Transport>,
        primary_is_ipv4: bool,
        time: f64,
    ) -> Self {
        let client = Self {
            state: ClientState::Disconnected,
            time,
            connect_start_time: 0.0,
            last_packet_send_time: -1000.0,
            last_packet_receive_time: -1000.0,
            should_disconnect: None,
            sequence: 0,
            client_index: 0,
            max_clients: 0,
            server_address_index: 0,
            server_address: None,
            connect_token: None,
            socket_ipv4,
            socket_ipv6,
            primary_is_ipv4,
            write_packet_key: [0; KEY_BYTES],
            read_packet_key: [0; KEY_BYTES],
            replay_protection: ReplayProtection::new(),
            packet_receive_queue: VecDeque::new(),
            challenge_token_sequence: 0,
            challenge_token_data: [0; CHALLENGE_TOKEN_BYTES],
        };

        info!("client started on port {}", client.port());

        client
    }

    /// Starts connecting to the servers listed in the connect token, trying each
    /// address in order until one accepts.
    ///
    /// Track progress by polling [`state`](Client::state) after each update. On an
    /// invalid token this returns an error and the client transitions to
    /// [`ClientState::InvalidConnectToken`].
    pub fn connect(&mut self, connect_token: &[u8; CONNECT_TOKEN_BYTES]) -> Result<(), Error> {
        self.disconnect();

        let connect_token = match ConnectToken::read(connect_token) {
            Ok(connect_token) => connect_token,
            Err(error) => {
                self.set_state(ClientState::InvalidConnectToken);
                return Err(error);
            }
        };

        self.server_address_index = 0;
        self.server_address = Some(connect_token.server_addresses[0]);

        if connect_token.server_addresses.len() == 1 {
            info!("client connecting to server {}", connect_token.server_addresses[0]);
        } else {
            info!(
                "client connecting to server {} [1/{}]",
                connect_token.server_addresses[0],
                connect_token.server_addresses.len()
            );
        }

        self.read_packet_key = connect_token.server_to_client_key;
        self.write_packet_key = connect_token.client_to_server_key;
        self.connect_token = Some(connect_token);

        self.reset_before_next_connect();
        self.set_state(ClientState::SendingConnectionRequest);

        Ok(())
    }

    /// Advances the client to the current time: receives and processes packets, sends
    /// queued packets and keep-alives, and applies timeouts.
    ///
    /// `time` must be monotonically non-decreasing across calls. Passing a value less
    /// than a previous call is not supported.
    pub fn update(&mut self, time: f64) {
        self.update_at(time, token::unix_timestamp());
    }

    pub(crate) fn update_at(&mut self, time: f64, current_timestamp: u64) {
        self.time = time;

        self.receive_packets(current_timestamp);
        self.send_packets();

        if self.state.is_connecting() {
            let connect_token = self.connect_token.as_ref().unwrap();
            let expire_seconds = connect_token.expire_timestamp - connect_token.create_timestamp;
            if self.time - self.connect_start_time >= expire_seconds as f64 {
                info!("client connect failed. connect token expired");
                self.disconnect_internal(ClientState::ConnectTokenExpired, false);
                return;
            }
        }

        if let Some(disconnect_state) = self.should_disconnect {
            debug!("client should disconnect -> {disconnect_state}");
            // only a client still connecting tries the next server address. a connected
            // client that receives a disconnect transitions straight to disconnected.
            if self.state.is_connecting() && self.connect_to_next_server() {
                return;
            }
            self.disconnect_internal(disconnect_state, false);
            return;
        }

        let timeout_seconds =
            self.connect_token.as_ref().map_or(0, |connect_token| connect_token.timeout_seconds);
        let timed_out =
            timeout_seconds > 0 && self.last_packet_receive_time + (timeout_seconds as f64) < time;
        if !timed_out {
            return;
        }

        match self.state {
            ClientState::SendingConnectionRequest => {
                info!("client connect failed. connection request timed out");
                if !self.connect_to_next_server() {
                    self.disconnect_internal(ClientState::ConnectionRequestTimedOut, false);
                }
            }
            ClientState::SendingConnectionResponse => {
                info!("client connect failed. connection response timed out");
                if !self.connect_to_next_server() {
                    self.disconnect_internal(ClientState::ConnectionResponseTimedOut, false);
                }
            }
            ClientState::Connected => {
                info!("client connection timed out");
                self.disconnect_internal(ClientState::ConnectionTimedOut, false);
            }
            _ => {}
        }
    }

    /// Sends a payload packet to the server. Does nothing unless the client is
    /// connected.
    pub fn send_packet(&mut self, payload: &[u8]) -> Result<(), Error> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }

        if self.state != ClientState::Connected {
            return Ok(());
        }

        self.send_packet_to_server(&Packet::Payload(payload.to_vec()));

        Ok(())
    }

    /// Pops the next payload packet received from the server, along with its sequence
    /// number.
    pub fn receive_packet(&mut self) -> Option<(Vec<u8>, u64)> {
        self.packet_receive_queue.pop_front()
    }

    /// Disconnects from the server, sending redundant disconnect packets so the
    /// server finds out quickly.
    pub fn disconnect(&mut self) {
        self.disconnect_internal(ClientState::Disconnected, true);
    }

    /// The current client state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// The slot this client occupies on the server, valid while connected.
    pub fn client_index(&self) -> usize {
        self.client_index
    }

    /// The number of client slots on the server, valid while connected.
    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    /// The sequence number of the next packet this client will send.
    pub fn next_packet_sequence(&self) -> u64 {
        self.sequence
    }

    /// The local port the client is bound to.
    pub fn port(&self) -> u16 {
        let socket = if self.primary_is_ipv4 {
            self.socket_ipv4.as_ref()
        } else {
            self.socket_ipv6.as_ref()
        };
        socket.and_then(|socket| socket.local_addr().ok()).map_or(0, |address| address.port())
    }

    /// The server address the client is currently connecting or connected to.
    pub fn server_address(&self) -> Option<SocketAddr> {
        self.server_address
    }

    // ----------------------------------------------------------------

    fn set_state(&mut self, state: ClientState) {
        debug!("client changed state from '{}' to '{}'", self.state, state);
        self.state = state;
    }

    fn reset_before_next_connect(&mut self) {
        self.connect_start_time = self.time;
        self.last_packet_send_time = self.time - 1.0;
        self.last_packet_receive_time = self.time;
        self.should_disconnect = None;
        self.challenge_token_sequence = 0;
        self.challenge_token_data = [0; CHALLENGE_TOKEN_BYTES];
        self.replay_protection.reset();
    }

    fn reset_connection_data(&mut self, state: ClientState) {
        self.sequence = 0;
        self.client_index = 0;
        self.max_clients = 0;
        self.connect_start_time = 0.0;
        self.server_address_index = 0;
        self.server_address = None;
        self.connect_token = None;
        self.write_packet_key = [0; KEY_BYTES];
        self.read_packet_key = [0; KEY_BYTES];
        self.set_state(state);
        self.reset_before_next_connect();
        self.packet_receive_queue.clear();
    }

    fn disconnect_internal(
        &mut self,
        destination_state: ClientState,
        send_disconnect_packets: bool,
    ) {
        debug_assert!(destination_state.is_disconnected());

        if self.state.is_disconnected() || self.state == destination_state {
            return;
        }

        info!("client disconnected");

        if send_disconnect_packets {
            debug!("client sent disconnect packets to server");
            for _ in 0..NUM_DISCONNECT_PACKETS {
                self.send_packet_to_server(&Packet::Disconnect);
            }
        }

        self.reset_connection_data(destination_state);
    }

    fn connect_to_next_server(&mut self) -> bool {
        let Some(connect_token) = self.connect_token.as_ref() else {
            return false;
        };
        let num_server_addresses = connect_token.server_addresses.len();

        if self.server_address_index + 1 >= num_server_addresses {
            debug!("client has no more servers to connect to");
            return false;
        }

        self.server_address_index += 1;
        let server_address = connect_token.server_addresses[self.server_address_index];
        self.server_address = Some(server_address);

        self.reset_before_next_connect();

        info!(
            "client connecting to next server {} [{}/{}]",
            server_address,
            self.server_address_index + 1,
            num_server_addresses
        );

        self.set_state(ClientState::SendingConnectionRequest);

        true
    }

    fn send_packets(&mut self) {
        if self.last_packet_send_time + 1.0 / PACKET_SEND_RATE >= self.time {
            return;
        }

        match self.state {
            ClientState::SendingConnectionRequest => {
                debug!("client sent connection request packet to server");
                let connect_token = self.connect_token.as_ref().unwrap();
                let packet = Packet::Request {
                    protocol_id: connect_token.protocol_id,
                    expire_timestamp: connect_token.expire_timestamp,
                    nonce: connect_token.nonce,
                    private_data: connect_token.private_data.clone(),
                };
                self.send_packet_to_server(&packet);
            }
            ClientState::SendingConnectionResponse => {
                debug!("client sent connection response packet to server");
                let packet = Packet::Response {
                    challenge_token_sequence: self.challenge_token_sequence,
                    challenge_token_data: self.challenge_token_data,
                };
                self.send_packet_to_server(&packet);
            }
            ClientState::Connected => {
                debug!("client sent connection keep alive packet to server");
                let packet = Packet::KeepAlive { client_index: 0, max_clients: 0 };
                self.send_packet_to_server(&packet);
            }
            _ => {}
        }
    }

    fn send_packet_to_server(&mut self, packet: &Packet) {
        let Some(server_address) = self.server_address else {
            return;
        };
        let protocol_id =
            self.connect_token.as_ref().map_or(0, |connect_token| connect_token.protocol_id);

        let mut packet_data = [0u8; MAX_PACKET_BYTES];
        let packet_bytes = match crate::packet::write_packet(
            packet,
            &mut packet_data,
            self.sequence,
            &self.write_packet_key,
            protocol_id,
        ) {
            Ok(packet_bytes) => packet_bytes,
            Err(_) => return,
        };
        self.sequence += 1;

        let socket = match server_address {
            SocketAddr::V4(_) => self.socket_ipv4.as_ref(),
            SocketAddr::V6(_) => self.socket_ipv6.as_ref(),
        };
        match socket {
            Some(socket) => {
                let _ = socket.send_to(&packet_data[..packet_bytes], server_address);
            }
            None => {
                debug!("client has no socket for server address family: {server_address}");
            }
        }

        self.last_packet_send_time = self.time;
    }

    fn receive_packets(&mut self, current_timestamp: u64) {
        let mut packet_data = [0u8; MAX_PACKET_BYTES];
        loop {
            // the client only talks to one server, so receive on the socket matching
            // the current server address family. the socket borrow is scoped to the
            // receive call so packet processing can borrow self mutably.
            let socket = match self.server_address {
                Some(SocketAddr::V4(_)) => self.socket_ipv4.as_ref(),
                Some(SocketAddr::V6(_)) => self.socket_ipv6.as_ref(),
                None => None,
            };
            let Some(socket) = socket else {
                return;
            };
            let Some((packet_bytes, from)) = socket::receive_packet(socket, &mut packet_data)
            else {
                return;
            };
            self.process_packet(from, &mut packet_data[..packet_bytes], current_timestamp);
        }
    }

    fn process_packet(&mut self, from: SocketAddr, packet_data: &mut [u8], current_timestamp: u64) {
        if Some(from) != self.server_address {
            return;
        }

        let Some(connect_token) = self.connect_token.as_ref() else {
            return;
        };

        let Some((packet, sequence)) = crate::packet::read_packet(
            packet_data,
            Some(&self.read_packet_key),
            connect_token.protocol_id,
            current_timestamp,
            None,
            AllowedPackets::CLIENT,
            Some(&mut self.replay_protection),
        ) else {
            return;
        };

        match packet {
            Packet::Denied => {
                if self.state == ClientState::SendingConnectionRequest
                    || self.state == ClientState::SendingConnectionResponse
                {
                    self.should_disconnect = Some(ClientState::ConnectionDenied);
                    self.last_packet_receive_time = self.time;
                }
            }

            Packet::Challenge { challenge_token_sequence, challenge_token_data } => {
                if self.state == ClientState::SendingConnectionRequest {
                    debug!("client received connection challenge packet from server");
                    self.challenge_token_sequence = challenge_token_sequence;
                    self.challenge_token_data = challenge_token_data;
                    self.last_packet_receive_time = self.time;
                    self.set_state(ClientState::SendingConnectionResponse);
                }
            }

            Packet::KeepAlive { client_index, max_clients }
                if max_clients == 0
                    || max_clients as usize > MAX_CLIENTS
                    || client_index >= max_clients =>
            {
                debug!(
                    "ignored connection keep alive packet. client index or max clients is out of range"
                );
            }

            Packet::KeepAlive { client_index, max_clients } => match self.state {
                ClientState::Connected => {
                    debug!("client received connection keep alive packet from server");
                    self.last_packet_receive_time = self.time;
                }
                ClientState::SendingConnectionResponse => {
                    debug!("client received connection keep alive packet from server");
                    self.last_packet_receive_time = self.time;
                    self.client_index = client_index as usize;
                    self.max_clients = max_clients as usize;
                    self.set_state(ClientState::Connected);
                    info!("client connected to server");
                }
                _ => {}
            },

            Packet::Payload(payload) => {
                if self.state == ClientState::Connected {
                    debug!("client received connection payload packet from server");
                    if self.packet_receive_queue.len() < PACKET_QUEUE_SIZE {
                        self.packet_receive_queue.push_back((payload, sequence));
                    }
                    self.last_packet_receive_time = self.time;
                }
            }

            Packet::Disconnect => {
                if self.state == ClientState::Connected {
                    debug!("client received disconnect packet from server");
                    self.should_disconnect = Some(ClientState::Disconnected);
                    self.last_packet_receive_time = self.time;
                }
            }

            Packet::Request { .. } | Packet::Response { .. } => unreachable!(),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.disconnect();
        self.write_packet_key.zeroize();
        self.read_packet_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::generate_connect_token_at;
    use crate::{Server, USER_DATA_BYTES, crypto};

    const TEST_PROTOCOL_ID: u64 = 0x1122334455667788;
    const TEST_TIMESTAMP: u64 = 1_000_000;

    #[test]
    fn state_predicates() {
        let error_states = [
            ClientState::ConnectTokenExpired,
            ClientState::InvalidConnectToken,
            ClientState::ConnectionTimedOut,
            ClientState::ConnectionResponseTimedOut,
            ClientState::ConnectionRequestTimedOut,
            ClientState::ConnectionDenied,
        ];
        for state in error_states {
            assert!(state.is_error());
            assert!(state.is_disconnected());
            assert!(!state.is_connecting());
        }

        assert!(!ClientState::Disconnected.is_error());
        assert!(ClientState::Disconnected.is_disconnected());
        assert!(!ClientState::Disconnected.is_connecting());

        for state in [ClientState::SendingConnectionRequest, ClientState::SendingConnectionResponse]
        {
            assert!(state.is_connecting());
            assert!(!state.is_error());
            assert!(!state.is_disconnected());
        }

        assert!(!ClientState::Connected.is_error());
        assert!(!ClientState::Connected.is_disconnected());
        assert!(!ClientState::Connected.is_connecting());
    }

    #[test]
    fn invalid_connect_token() {
        let network = socket::MemoryNetwork::new();
        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        let connect_token = [0u8; CONNECT_TOKEN_BYTES];
        assert!(client.connect(&connect_token).is_err());
        assert_eq!(client.state(), ClientState::InvalidConnectToken);
    }

    #[test]
    fn in_memory_connection_request_times_out() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let dead_server: SocketAddr = "127.0.0.1:40001".parse().unwrap();

        let token = generate_connect_token_at(
            &[dead_server],
            &[dead_server],
            TEST_TIMESTAMP,
            30,
            5,
            1,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        client.connect(&token).unwrap();
        assert_eq!(client.state(), ClientState::SendingConnectionRequest);

        let mut time = 0.0;
        while time <= 5.0 {
            client.update_at(time, TEST_TIMESTAMP);
            assert_eq!(client.state(), ClientState::SendingConnectionRequest);
            time += 0.5;
        }
        client.update_at(time, TEST_TIMESTAMP + 6);
        assert_eq!(client.state(), ClientState::ConnectionRequestTimedOut);
    }

    #[test]
    fn in_memory_connection_response_times_out() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            "127.0.0.1:40000".parse().unwrap(),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            30,
            5,
            1,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        client.connect(&token).unwrap();

        // First exchange delivers the request to the server and the challenge back to the client.
        client.update_at(0.0, TEST_TIMESTAMP);
        server.update_at(0.0, TEST_TIMESTAMP);
        client.update_at(0.1, TEST_TIMESTAMP);
        assert_eq!(client.state(), ClientState::SendingConnectionResponse);

        // Stop the server so the client's connection response never receives a keep-alive.
        server.stop();

        let mut time = 0.2;
        while time <= 5.1 {
            client.update_at(time, TEST_TIMESTAMP);
            assert_eq!(client.state(), ClientState::SendingConnectionResponse);
            time += 0.5;
        }
        client.update_at(time, TEST_TIMESTAMP + 6);
        assert_eq!(client.state(), ClientState::ConnectionResponseTimedOut);
    }

    #[test]
    fn in_memory_established_connection_times_out() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            "127.0.0.1:40000".parse().unwrap(),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            30,
            5,
            1,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        client.connect(&token).unwrap();

        let mut time = 0.0;
        for _ in 0..5 {
            client.update_at(time, TEST_TIMESTAMP);
            server.update_at(time, TEST_TIMESTAMP);
            time += 0.1;
        }
        assert_eq!(client.state(), ClientState::Connected);

        // Server stops sending packets; client times out after 5 seconds.
        for _ in 0..60 {
            time += 0.1;
            client.update_at(time, TEST_TIMESTAMP + 6);
        }
        assert_eq!(client.state(), ClientState::ConnectionTimedOut);
    }

    #[test]
    fn in_memory_connect_token_expires_while_connecting() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let dead_server: SocketAddr = "127.0.0.1:40001".parse().unwrap();

        // expire_seconds = 3, timeout_seconds = 10 -> token expires before request timeout.
        let token = generate_connect_token_at(
            &[dead_server],
            &[dead_server],
            TEST_TIMESTAMP,
            3,
            10,
            1,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        client.connect(&token).unwrap();

        client.update_at(2.9, TEST_TIMESTAMP + 2);
        assert_eq!(client.state(), ClientState::SendingConnectionRequest);

        client.update_at(3.0, TEST_TIMESTAMP + 3);
        assert_eq!(client.state(), ClientState::ConnectTokenExpired);
    }

    #[test]
    fn in_memory_multi_address_failover_and_dual_stack_ipv6() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let dead_v4: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let live_v6: SocketAddr = "[::1]:40002".parse().unwrap();

        let mut server =
            Server::new_in_memory(&network, live_v6, TEST_PROTOCOL_ID, &private_key, 0.0).unwrap();
        server.start_at(2, TEST_TIMESTAMP).unwrap();

        let token = generate_connect_token_at(
            &[dead_v4, server.address()],
            &[dead_v4, server.address()],
            TEST_TIMESTAMP,
            30,
            2,
            42,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0x77; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_dual_in_memory(
            &network,
            "127.0.0.1:0".parse().unwrap(),
            "[::1]:0".parse().unwrap(),
            0.0,
        )
        .unwrap();
        client.connect(&token).unwrap();
        assert_eq!(client.server_address(), Some(dead_v4));

        // Advance past the 2s timeout on dead_v4 so the client fails over to live_v6.
        let mut time = 0.0;
        while client.server_address() == Some(dead_v4) {
            time += 0.25;
            client.update_at(time, TEST_TIMESTAMP + 2);
            server.update_at(time, TEST_TIMESTAMP + 2);
        }
        assert_eq!(client.server_address(), Some(server.address()));
        assert_eq!(client.state(), ClientState::SendingConnectionRequest);

        // Complete handshake and exchange payload over IPv6.
        for _ in 0..10 {
            time += 0.1;
            client.update_at(time, TEST_TIMESTAMP + 3);
            server.update_at(time, TEST_TIMESTAMP + 3);
        }
        assert_eq!(client.state(), ClientState::Connected);
        assert_eq!(server.num_connected_clients(), 1);

        client.send_packet(b"hello ipv6").unwrap();
        server.send_packet(0, b"world ipv6").unwrap();
        time += 0.1;
        server.update_at(time, TEST_TIMESTAMP + 3);
        client.update_at(time, TEST_TIMESTAMP + 3);

        assert_eq!(server.receive_packet(0).unwrap().0, b"hello ipv6");
        assert_eq!(client.receive_packet().unwrap().0, b"world ipv6");
    }

    #[test]
    fn in_memory_negative_timeout_and_never_expiring_token() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            "127.0.0.1:40000".parse().unwrap(),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            -1,
            -1,
            99,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        client.connect(&token).unwrap();

        let mut time = 0.0;
        for _ in 0..5 {
            client.update_at(time, TEST_TIMESTAMP);
            server.update_at(time, TEST_TIMESTAMP);
            time += 0.1;
        }
        assert_eq!(client.state(), ClientState::Connected);

        // Jump 1000 seconds without exchanging packets: negative timeout disables timeouts.
        time += 1000.0;
        client.update_at(time, TEST_TIMESTAMP + 1000);
        server.update_at(time, TEST_TIMESTAMP + 1000);
        assert_eq!(client.state(), ClientState::Connected);
        assert_eq!(server.num_connected_clients(), 1);
    }

    #[test]
    fn packets_from_an_unexpected_address_are_ignored() {
        const PROTOCOL_ID: u64 = 0x1122334455667788;
        const OTHER_SEQUENCE: u64 = 1000;
        const SERVER_SEQUENCE: u64 = 1;

        let network = socket::MemoryNetwork::new();
        let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let other_address: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let private_key = crypto::generate_key();
        let connect_token = generate_connect_token_at(
            &[server_address],
            &[server_address],
            TEST_TIMESTAMP,
            30,
            5,
            0x1234,
            PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, "127.0.0.1:0".parse().unwrap(), 0.0);
        client.connect(&connect_token).unwrap();
        client.state = ClientState::Connected;

        let key = ConnectToken::read(&connect_token).unwrap().server_to_client_key;
        let mut packet_data = [0u8; MAX_PACKET_BYTES];

        let packet_bytes = crate::packet::write_packet(
            &Packet::Payload(vec![1, 2, 3]),
            &mut packet_data,
            OTHER_SEQUENCE,
            &key,
            PROTOCOL_ID,
        )
        .unwrap();
        client.process_packet(other_address, &mut packet_data[..packet_bytes], TEST_TIMESTAMP);
        assert!(
            !client.replay_protection.already_received(OTHER_SEQUENCE),
            "a packet from an address other than the server address advanced replay protection"
        );
        assert!(client.receive_packet().is_none());

        let packet_bytes = crate::packet::write_packet(
            &Packet::Payload(vec![4, 5, 6]),
            &mut packet_data,
            SERVER_SEQUENCE,
            &key,
            PROTOCOL_ID,
        )
        .unwrap();
        client.process_packet(server_address, &mut packet_data[..packet_bytes], TEST_TIMESTAMP);
        assert_eq!(client.receive_packet(), Some((vec![4, 5, 6], SERVER_SEQUENCE)));
    }

    #[test]
    fn keep_alive_with_client_slot_out_of_range_is_ignored() {
        const PROTOCOL_ID: u64 = 0x1122334455667788;
        const CLIENT_INDEX: usize = 3;
        const MAX_SLOTS: u32 = MAX_CLIENTS as u32;

        let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let private_key = crate::generate_key();
        let connect_token = generate_connect_token_at(
            &[server_address],
            &[server_address],
            TEST_TIMESTAMP,
            30,
            5,
            0x1234,
            PROTOCOL_ID,
            &private_key,
            &[0; crate::USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::create(None, None, true, 1000.0).unwrap();
        client.connect(&connect_token).unwrap();
        client.state = ClientState::SendingConnectionResponse;
        client.client_index = CLIENT_INDEX;
        client.max_clients = 7;

        let key = ConnectToken::read(&connect_token).unwrap().server_to_client_key;
        let mut packet_data = [0u8; MAX_PACKET_BYTES];

        let cases = [(u32::MAX, MAX_SLOTS), (0, 0), (0, MAX_SLOTS + 1), (5, 5), (6, 5)];
        for (sequence, (client_index, max_clients)) in (1u64..).zip(cases) {
            let packet_bytes = crate::packet::write_packet(
                &Packet::KeepAlive { client_index, max_clients },
                &mut packet_data,
                sequence,
                &key,
                PROTOCOL_ID,
            )
            .unwrap();
            client.process_packet(server_address, &mut packet_data[..packet_bytes], TEST_TIMESTAMP);
            assert_eq!(client.client_index(), CLIENT_INDEX);
            assert_eq!(client.max_clients(), 7);
            assert_eq!(client.state(), ClientState::SendingConnectionResponse);
        }
    }
}
