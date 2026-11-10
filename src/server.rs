//! The netcode server.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use log::{debug, error, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::packet::{AllowedPackets, Packet};
use crate::replay::ReplayProtection;
use crate::token::{
    self, CHALLENGE_TOKEN_BYTES, CONNECT_TOKEN_PRIVATE_BYTES, ChallengeToken, PrivateConnectToken,
};
use crate::{
    Error, KEY_BYTES, Key, MAC_BYTES, MAX_CLIENTS, MAX_PACKET_BYTES, MAX_PAYLOAD_BYTES,
    NUM_DISCONNECT_PACKETS, PACKET_QUEUE_SIZE, PACKET_SEND_RATE, USER_DATA_BYTES, UserData, crypto,
    socket,
};

/// Why a client was disconnected from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// No packets were received from the client within the timeout period.
    TimedOut,
    /// The client sent a disconnect packet.
    ClientDisconnect,
    /// The server disconnected the client.
    ServerDisconnect,
}

/// A connection event on the server, drained with [`Server::next_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEvent {
    /// A client connected.
    ClientConnected {
        /// The slot the client was assigned.
        client_index: usize,
    },
    /// A client disconnected.
    ClientDisconnected {
        /// The slot the client occupied. It is free again by the time this event is
        /// observed.
        client_index: usize,
        /// Why the client was disconnected.
        reason: DisconnectReason,
    },
}

// ----------------------------------------------------------------

const MAX_ENCRYPTION_MAPPINGS: usize = MAX_CLIENTS * 4;

/// The most connect and disconnect events queued for [`Server::next_event`]. Once
/// full, each new event drops the oldest one.
const MAX_SERVER_EVENTS: usize = MAX_CLIENTS * 4;

/// Configuration for a [`Server`].
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// The longest lifetime, in seconds, of connect tokens issued by the backend.
    /// A token whose expiry is at or before the server start time plus this lifetime
    /// is rejected. Values at or below zero use
    /// [`crate::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME`].
    pub max_connect_token_lifetime: i32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { max_connect_token_lifetime: crate::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME }
    }
}

/// Maps packet source addresses to the encryption keys from their connect token.
/// An entry is added when a connection request is accepted and expires after
/// `timeout` seconds without packets, or at `expire_time` if the client never
/// finishes connecting.
struct EncryptionEntry {
    address: Option<SocketAddr>,
    timeout_seconds: i32,
    expire_time: f64,
    last_access_time: f64,
    client_index: Option<usize>,
    connect_token_entry_index: Option<usize>,
    send_key: Key,
    receive_key: Key,
}

impl EncryptionEntry {
    fn new() -> Self {
        Self {
            address: None,
            timeout_seconds: 0,
            expire_time: -1.0,
            last_access_time: -1000.0,
            client_index: None,
            connect_token_entry_index: None,
            send_key: [0; KEY_BYTES],
            receive_key: [0; KEY_BYTES],
        }
    }

    fn expired(&self, time: f64) -> bool {
        (self.timeout_seconds > 0 && self.last_access_time + (self.timeout_seconds as f64) < time)
            || (self.expire_time >= 0.0 && self.expire_time < time)
    }
}

impl Drop for EncryptionEntry {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

impl ZeroizeOnDrop for EncryptionEntry {}

struct EncryptionManager {
    entries: Vec<EncryptionEntry>,
    /// One past the highest slot ever used, so lookups scan only the live prefix.
    num_entries: usize,
}

impl EncryptionManager {
    fn new() -> Self {
        Self {
            entries: (0..MAX_ENCRYPTION_MAPPINGS).map(|_| EncryptionEntry::new()).collect(),
            num_entries: 0,
        }
    }

    fn reset(&mut self) {
        debug!("reset encryption manager");
        *self = Self::new();
    }

    #[allow(clippy::too_many_arguments)]
    fn add_encryption_mapping(
        &mut self,
        address: SocketAddr,
        send_key: &Key,
        receive_key: &Key,
        time: f64,
        expire_time: f64,
        timeout_seconds: i32,
        connect_token_entry_index: usize,
    ) -> bool {
        for index in 0..self.num_entries {
            let entry = &mut self.entries[index];
            if entry.address == Some(address) && !entry.expired(time) {
                entry.timeout_seconds = timeout_seconds;
                entry.expire_time = expire_time;
                entry.last_access_time = time;
                entry.send_key = *send_key;
                entry.receive_key = *receive_key;
                entry.connect_token_entry_index = Some(connect_token_entry_index);
                return true;
            }
        }

        for index in 0..MAX_ENCRYPTION_MAPPINGS {
            let entry = &mut self.entries[index];
            if entry.address.is_none() || (entry.expired(time) && entry.client_index.is_none()) {
                *entry = EncryptionEntry {
                    address: Some(address),
                    timeout_seconds,
                    expire_time,
                    last_access_time: time,
                    client_index: None,
                    connect_token_entry_index: Some(connect_token_entry_index),
                    send_key: *send_key,
                    receive_key: *receive_key,
                };
                if index + 1 > self.num_entries {
                    self.num_entries = index + 1;
                }
                return true;
            }
        }

        false
    }

    fn remove_encryption_mapping(&mut self, address: SocketAddr, time: f64) -> bool {
        for index in 0..self.num_entries {
            if self.entries[index].address != Some(address) {
                continue;
            }

            self.entries[index] = EncryptionEntry::new();

            // shrink the live prefix past any expired unowned entries at the end
            if index + 1 == self.num_entries {
                let mut last = index;
                while last > 0 {
                    let entry = &self.entries[last - 1];
                    if !entry.expired(time) || entry.client_index.is_some() {
                        break;
                    }
                    self.entries[last - 1] = EncryptionEntry::new();
                    last -= 1;
                }
                self.num_entries = last;
            }

            return true;
        }

        false
    }

    /// Frees expired mappings, wiping their keys. A mapping owned by a connected
    /// client is kept: it goes only when that client disconnects.
    fn remove_expired_mappings(&mut self, time: f64) {
        for entry in &mut self.entries[..self.num_entries] {
            if entry.client_index.is_none() && entry.expired(time) {
                *entry = EncryptionEntry::new();
            }
        }
    }

    fn find_encryption_mapping(&mut self, address: SocketAddr, time: f64) -> Option<usize> {
        for index in 0..self.num_entries {
            let entry = &mut self.entries[index];
            if entry.address == Some(address) && !entry.expired(time) {
                entry.last_access_time = time;
                return Some(index);
            }
        }
        None
    }

    fn touch(&mut self, index: usize, address: SocketAddr, time: f64) -> bool {
        if self.entries[index].address != Some(address) {
            return false;
        }
        self.entries[index].last_access_time = time;
        true
    }

    fn set_expire_time(&mut self, index: usize, expire_time: f64) {
        self.entries[index].expire_time = expire_time;
    }

    fn set_client_index(&mut self, index: usize, client_index: Option<usize>) {
        self.entries[index].client_index = client_index;
    }

    fn connect_token_entry_index(&self, index: usize) -> Option<usize> {
        self.entries[index].connect_token_entry_index
    }

    fn send_key(&self, index: usize) -> &Key {
        &self.entries[index].send_key
    }

    fn receive_key(&self, index: usize) -> &Key {
        &self.entries[index].receive_key
    }

    fn timeout(&self, index: usize) -> i32 {
        self.entries[index].timeout_seconds
    }
}

/// The expire time of the encryption mapping a connection request installs before
/// the handshake completes. A negative token timeout bounds it by the connect token's
/// remaining lifetime, with the server's maximum token lifetime as the ceiling for a
/// token that does not expire; the mapping is switched to no expiry once the client
/// connects.
fn pending_mapping_expire_time(
    time: f64,
    timeout_seconds: i32,
    expire_timestamp: u64,
    current_timestamp: u64,
    max_connect_token_lifetime: u64,
) -> f64 {
    if timeout_seconds >= 0 {
        return time + timeout_seconds as f64;
    }
    let token_lifetime = if expire_timestamp == u64::MAX {
        max_connect_token_lifetime
    } else {
        expire_timestamp.saturating_sub(current_timestamp)
    };
    time + token_lifetime as f64
}

// ----------------------------------------------------------------

const MAX_CONNECT_TOKEN_ENTRIES: usize = MAX_CLIENTS * 8;

/// A history of connect tokens seen by the server, keyed by token HMAC, so a token
/// stolen off the wire cannot be replayed from a different address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectTokenEntryState {
    Free,
    Pending,
    Consumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectTokenEntryResult {
    Accepted(usize),
    Refused,
    HistoryFull,
}

struct ConnectTokenEntry {
    state: ConnectTokenEntryState,
    #[allow(dead_code)]
    time: f64,
    /// A token minted with negative `expire_seconds` stores `u64::MAX`, so this entry
    /// never expires and its slot is never reused during the server run (development
    /// and testing only).
    expire_timestamp: u64,
    mac: [u8; MAC_BYTES],
    address: Option<SocketAddr>,
}

fn reset_connect_token_entries(entries: &mut Vec<ConnectTokenEntry>) {
    entries.clear();
    entries.extend((0..MAX_CONNECT_TOKEN_ENTRIES).map(|_| ConnectTokenEntry {
        state: ConnectTokenEntryState::Free,
        time: -1000.0,
        expire_timestamp: 0,
        mac: [0; MAC_BYTES],
        address: None,
    }));
}

/// Returns the history entry that admits this connection request.
fn find_or_add_connect_token_entry(
    entries: &mut [ConnectTokenEntry],
    address: SocketAddr,
    mac: &[u8; MAC_BYTES],
    expire_timestamp: u64,
    current_timestamp: u64,
    time: f64,
) -> ConnectTokenEntryResult {
    // Find the matching entry for the token MAC and the first slot that is free
    // or whose token has expired. The scan is constant time in the worst case.
    // This is intentional so token history timing does not reveal whether a token
    // was seen before.
    let mut matching_index = None;
    let mut free_index = None;

    for (index, entry) in entries.iter().enumerate() {
        if entry.state != ConnectTokenEntryState::Free && &entry.mac == mac {
            matching_index = Some(index);
        }
        if free_index.is_none()
            && (entry.state == ConnectTokenEntryState::Free
                || entry.expire_timestamp <= current_timestamp)
        {
            free_index = Some(index);
        }
    }

    match matching_index {
        None => {
            let Some(index) = free_index else {
                return ConnectTokenEntryResult::HistoryFull;
            };
            entries[index] = ConnectTokenEntry {
                state: ConnectTokenEntryState::Pending,
                time,
                expire_timestamp,
                mac: *mac,
                address: Some(address),
            };
            ConnectTokenEntryResult::Accepted(index)
        }
        Some(index) => {
            if entries[index].state == ConnectTokenEntryState::Pending
                && entries[index].address == Some(address)
            {
                ConnectTokenEntryResult::Accepted(index)
            } else {
                ConnectTokenEntryResult::Refused
            }
        }
    }
}

fn consume_connect_token_entry(entries: &mut [ConnectTokenEntry], index: usize) {
    entries[index].state = ConnectTokenEntryState::Consumed;
}

// ----------------------------------------------------------------

struct ClientSlot {
    connected: bool,
    confirmed: bool,
    client_id: u64,
    timeout_seconds: i32,
    encryption_index: Option<usize>,
    address: Option<SocketAddr>,
    sequence: u64,
    last_packet_send_time: f64,
    last_packet_receive_time: f64,
    user_data: UserData,
    replay_protection: ReplayProtection,
    packet_queue: VecDeque<(Vec<u8>, u64)>,
}

impl ClientSlot {
    fn new() -> Self {
        Self {
            connected: false,
            confirmed: false,
            client_id: 0,
            timeout_seconds: 0,
            encryption_index: None,
            address: None,
            sequence: 0,
            last_packet_send_time: 0.0,
            last_packet_receive_time: 0.0,
            user_data: [0; USER_DATA_BYTES],
            replay_protection: ReplayProtection::new(),
            packet_queue: VecDeque::new(),
        }
    }
}

/// A netcode dedicated server.
///
/// Create it with the public address clients connect to, [`start`](Server::start) it
/// with a number of client slots, then drive it by calling [`update`](Server::update)
/// once per frame with the current time. All methods must be called from one thread;
/// the server performs no internal synchronization.
pub struct Server {
    protocol_id: u64,
    private_key: Key,
    max_connect_token_lifetime: u64,
    socket: socket::Transport,
    public_address: SocketAddr,
    time: f64,
    running: bool,
    max_clients: usize,
    num_connected_clients: usize,
    global_sequence: u64,
    challenge_sequence: u64,
    min_connect_token_expire_timestamp: u64,
    challenge_key: Key,
    clients: Vec<ClientSlot>,
    connect_token_entries: Vec<ConnectTokenEntry>,
    encryption_manager: EncryptionManager,
    events: VecDeque<ServerEvent>,
}

impl Server {
    /// Creates a server that clients reach at `public_address`. The server binds a
    /// socket on that port on all interfaces of the same address family.
    ///
    /// `protocol_id` is a 64-bit value unique to this game or application, and
    /// `private_key` is shared between the web backend and the dedicated servers.
    ///
    /// A public address with port 0 binds an ephemeral port and advertises it as the
    /// public port, which is convenient for tests running on localhost.
    pub fn new(
        public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        time: f64,
    ) -> Result<Self, Error> {
        Self::new_with_config(
            public_address,
            protocol_id,
            private_key,
            ServerConfig::default(),
            time,
        )
    }

    /// Creates a server with explicit configuration.
    pub fn new_with_config(
        public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        config: ServerConfig,
        time: f64,
    ) -> Result<Self, Error> {
        let bind_address: SocketAddr = match public_address {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, public_address.port()).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, public_address.port()).into(),
        };
        let socket = socket::create_socket(bind_address)?;
        Self::with_transport(socket, public_address, protocol_id, private_key, config, time)
    }

    #[cfg(test)]
    pub(crate) fn new_in_memory(
        network: &socket::MemoryNetwork,
        public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        time: f64,
    ) -> Result<Self, Error> {
        Self::new_in_memory_with_config(
            network,
            public_address,
            protocol_id,
            private_key,
            ServerConfig::default(),
            time,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_in_memory_with_config(
        network: &socket::MemoryNetwork,
        public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        config: ServerConfig,
        time: f64,
    ) -> Result<Self, Error> {
        let socket = socket::Transport::Memory(network.bind(public_address));
        let bound_address = socket.local_addr()?;
        Self::with_transport(socket, bound_address, protocol_id, private_key, config, time)
    }

    fn with_transport(
        socket: socket::Transport,
        mut public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        config: ServerConfig,
        time: f64,
    ) -> Result<Self, Error> {
        if public_address.port() == 0 {
            public_address.set_port(socket.local_addr()?.port());
        }

        info!("server listening on {public_address}");

        let mut connect_token_entries = Vec::new();
        reset_connect_token_entries(&mut connect_token_entries);

        Ok(Self {
            protocol_id,
            private_key: *private_key,
            max_connect_token_lifetime: if config.max_connect_token_lifetime > 0 {
                config.max_connect_token_lifetime as u64
            } else {
                crate::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME as u64
            },
            socket,
            public_address,
            time,
            running: false,
            max_clients: 0,
            num_connected_clients: 0,
            global_sequence: 1 << 63,
            challenge_sequence: 0,
            min_connect_token_expire_timestamp: 0,
            challenge_key: [0; KEY_BYTES],
            clients: Vec::new(),
            connect_token_entries,
            encryption_manager: EncryptionManager::new(),
            events: VecDeque::new(),
        })
    }

    /// Starts the server with `max_clients` client slots, in `[1, MAX_CLIENTS]`.
    /// If the server is already running it is stopped first, disconnecting everyone.
    pub fn start(&mut self, max_clients: usize) -> Result<(), Error> {
        self.start_at(max_clients, token::unix_timestamp())
    }

    pub(crate) fn start_at(
        &mut self,
        max_clients: usize,
        current_timestamp: u64,
    ) -> Result<(), Error> {
        if max_clients == 0 || max_clients > MAX_CLIENTS {
            return Err(Error::InvalidMaxClients(max_clients));
        }

        if self.running {
            self.stop();
        }

        info!("server started with {max_clients} client slots");

        self.running = true;
        self.max_clients = max_clients;
        self.num_connected_clients = 0;
        self.challenge_sequence = 0;
        self.challenge_key = crypto::generate_key();
        self.min_connect_token_expire_timestamp =
            current_timestamp.saturating_add(self.max_connect_token_lifetime);
        // global packets (challenge, denied) encrypt with the same per-token
        // server-to-client keys as per-client packets, whose sequences start at zero,
        // so the global sequence takes the top half of the space to keep AEAD nonces
        // disjoint under a shared key
        self.global_sequence = 1 << 63;
        self.clients = (0..max_clients).map(|_| ClientSlot::new()).collect();

        Ok(())
    }

    /// Stops the server, disconnecting all clients.
    pub fn stop(&mut self) {
        if !self.running {
            return;
        }

        self.disconnect_all_clients();

        self.running = false;
        self.max_clients = 0;
        self.num_connected_clients = 0;
        self.global_sequence = 1 << 63;
        self.challenge_sequence = 0;
        self.challenge_key = [0; KEY_BYTES];
        self.min_connect_token_expire_timestamp = 0;
        self.clients.clear();
        self.events.clear();

        reset_connect_token_entries(&mut self.connect_token_entries);
        self.encryption_manager.reset();

        info!("server stopped");
    }

    /// Advances the server to the current time: receives and processes packets, sends
    /// keep-alives, and times out unresponsive clients.
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
        self.check_for_timeouts();
    }

    /// Pops the next connect or disconnect event. Drain these every update: at most
    /// `MAX_CLIENTS * 4` events are kept, the oldest dropped first, and
    /// [`Server::stop`] clears them.
    pub fn next_event(&mut self) -> Option<ServerEvent> {
        self.events.pop_front()
    }

    /// Sends a payload packet to the client in the given slot. Does nothing unless
    /// that client is connected.
    pub fn send_packet(&mut self, client_index: usize, payload: &[u8]) -> Result<(), Error> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidPayloadSize(payload.len()));
        }

        if !self.running
            || client_index >= self.max_clients
            || !self.clients[client_index].connected
        {
            return Ok(());
        }

        // until the client is confirmed, prefix each payload with a keep-alive so it
        // learns its client index and max clients as early as possible
        if !self.clients[client_index].confirmed {
            let keep_alive = Packet::KeepAlive {
                client_index: client_index as u32,
                max_clients: self.max_clients as u32,
            };
            self.send_client_packet(&keep_alive, client_index);
        }

        self.send_client_packet(&Packet::Payload(payload.to_vec()), client_index);

        Ok(())
    }

    /// Pops the next payload packet received from the client in the given slot, along
    /// with its sequence number.
    pub fn receive_packet(&mut self, client_index: usize) -> Option<(Vec<u8>, u64)> {
        if !self.running || client_index >= self.max_clients {
            return None;
        }
        self.clients[client_index].packet_queue.pop_front()
    }

    /// Disconnects the client in the given slot, sending redundant disconnect packets
    /// so it finds out quickly.
    pub fn disconnect_client(&mut self, client_index: usize) {
        if !self.running
            || client_index >= self.max_clients
            || !self.clients[client_index].connected
        {
            return;
        }
        self.disconnect_client_internal(client_index, true, DisconnectReason::ServerDisconnect);
    }

    /// Disconnects all connected clients.
    pub fn disconnect_all_clients(&mut self) {
        if !self.running {
            return;
        }
        for client_index in 0..self.max_clients {
            if self.clients[client_index].connected {
                self.disconnect_client_internal(
                    client_index,
                    true,
                    DisconnectReason::ServerDisconnect,
                );
            }
        }
    }

    /// Whether the server is running.
    pub fn running(&self) -> bool {
        self.running
    }

    /// The number of client slots, or 0 when the server is not running.
    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    /// The number of connected clients.
    pub fn num_connected_clients(&self) -> usize {
        self.num_connected_clients
    }

    /// Whether a client is connected in the given slot.
    pub fn client_connected(&self, client_index: usize) -> bool {
        self.running && client_index < self.max_clients && self.clients[client_index].connected
    }

    /// The client id of the client in the given slot, or 0 if none is connected.
    pub fn client_id(&self, client_index: usize) -> u64 {
        if !self.client_connected(client_index) {
            return 0;
        }
        self.clients[client_index].client_id
    }

    /// The address of the client in the given slot.
    pub fn client_address(&self, client_index: usize) -> Option<SocketAddr> {
        if !self.client_connected(client_index) {
            return None;
        }
        self.clients[client_index].address
    }

    /// The user data carried in the connect token of the client in the given slot.
    pub fn client_user_data(&self, client_index: usize) -> Option<&UserData> {
        if !self.client_connected(client_index) {
            return None;
        }
        Some(&self.clients[client_index].user_data)
    }

    /// The sequence number of the next packet the server will send to the client in
    /// the given slot.
    pub fn next_packet_sequence(&self, client_index: usize) -> u64 {
        if !self.client_connected(client_index) {
            return 0;
        }
        self.clients[client_index].sequence
    }

    /// The port the server socket is bound to.
    pub fn port(&self) -> u16 {
        self.public_address.port()
    }

    /// The public address clients connect to.
    pub fn address(&self) -> SocketAddr {
        self.public_address
    }

    // ----------------------------------------------------------------

    fn find_client_index_by_address(&self, address: SocketAddr) -> Option<usize> {
        self.clients[..self.max_clients]
            .iter()
            .position(|client| client.connected && client.address == Some(address))
    }

    fn find_client_index_by_id(&self, client_id: u64) -> Option<usize> {
        self.clients[..self.max_clients]
            .iter()
            .position(|client| client.connected && client.client_id == client_id)
    }

    fn find_free_client_index(&self) -> Option<usize> {
        self.clients[..self.max_clients].iter().position(|client| !client.connected)
    }

    fn receive_packets(&mut self, current_timestamp: u64) {
        self.receive_packets_with(current_timestamp, |server, buffer| {
            socket::receive_packet(&server.socket, buffer)
        });
    }

    /// One receive drain: reads and processes packets until `receive` reports the
    /// receive queue is empty. Parameterised over the receive call so the drain can be
    /// exercised without a live socket.
    fn receive_packets_with(
        &mut self,
        current_timestamp: u64,
        mut receive: impl FnMut(&Self, &mut [u8]) -> Option<(usize, SocketAddr)>,
    ) {
        let mut packet_data = [0u8; MAX_PACKET_BYTES];
        while let Some((packet_bytes, from)) = receive(self, &mut packet_data) {
            self.read_and_process_packet(from, &mut packet_data[..packet_bytes], current_timestamp);
        }
    }

    fn read_and_process_packet(
        &mut self,
        from: SocketAddr,
        packet_data: &mut [u8],
        current_timestamp: u64,
    ) {
        if !self.running || packet_data.len() <= 1 {
            return;
        }

        let client_index = self.find_client_index_by_address(from);
        let encryption_index = match client_index {
            Some(client_index) => self.clients[client_index].encryption_index,
            None => self.encryption_manager.find_encryption_mapping(from, self.time),
        };

        let read_packet_key = encryption_index
            .map(|encryption_index| self.encryption_manager.receive_key(encryption_index));

        if read_packet_key.is_none() && packet_data[0] != 0 {
            debug!(
                "server could not process packet because no encryption mapping exists for {from}"
            );
            return;
        }

        let protocol_id = self.protocol_id;
        let replay_protection =
            client_index.map(|client_index| &mut self.clients[client_index].replay_protection);

        let Some((packet, sequence)) =
            crate::packet::read_packet_with_min_connect_token_expire_timestamp(
                packet_data,
                read_packet_key,
                protocol_id,
                current_timestamp,
                Some(&self.private_key),
                AllowedPackets::SERVER,
                replay_protection,
                self.min_connect_token_expire_timestamp,
            )
        else {
            return;
        };

        self.process_packet(
            from,
            packet,
            sequence,
            encryption_index,
            client_index,
            current_timestamp,
        );
    }

    fn process_packet(
        &mut self,
        from: SocketAddr,
        packet: Packet,
        sequence: u64,
        encryption_index: Option<usize>,
        client_index: Option<usize>,
        current_timestamp: u64,
    ) {
        match packet {
            Packet::Request { expire_timestamp, mut private_data, .. } => {
                debug!("server received connection request from {from}");
                self.process_connection_request(
                    from,
                    &private_data,
                    expire_timestamp,
                    current_timestamp,
                );
                private_data.zeroize();
            }

            Packet::Response { challenge_token_sequence, challenge_token_data } => {
                debug!("server received connection response from {from}");
                self.process_connection_response(
                    from,
                    challenge_token_sequence,
                    challenge_token_data,
                    encryption_index,
                );
            }

            Packet::KeepAlive { .. } => {
                if let Some(client_index) = client_index {
                    debug!(
                        "server received connection keep alive packet from client {client_index}"
                    );
                    self.touch_client(client_index);
                }
            }

            Packet::Payload(payload) => {
                if let Some(client_index) = client_index {
                    debug!("server received connection payload packet from client {client_index}");
                    self.touch_client(client_index);
                    let queue = &mut self.clients[client_index].packet_queue;
                    if queue.len() < PACKET_QUEUE_SIZE {
                        queue.push_back((payload, sequence));
                    }
                }
            }

            Packet::Disconnect => {
                if let Some(client_index) = client_index {
                    debug!("server received disconnect packet from client {client_index}");
                    self.disconnect_client_internal(
                        client_index,
                        false,
                        DisconnectReason::ClientDisconnect,
                    );
                }
            }

            Packet::Denied | Packet::Challenge { .. } => unreachable!(),
        }
    }

    /// Marks the client as heard from, confirming it on first contact.
    fn touch_client(&mut self, client_index: usize) {
        let client = &mut self.clients[client_index];
        client.last_packet_receive_time = self.time;
        if !client.confirmed {
            debug!("server confirmed connection with client {client_index}");
            client.confirmed = true;
        }
    }

    /// Processes a connection request packet. The private connect token data has
    /// already been decrypted; its trailing 16 bytes still hold the original HMAC,
    /// which keys the used-token history.
    fn process_connection_request(
        &mut self,
        from: SocketAddr,
        private_data: &[u8; CONNECT_TOKEN_PRIVATE_BYTES],
        expire_timestamp: u64,
        current_timestamp: u64,
    ) {
        let Ok(private_token) = PrivateConnectToken::read(&private_data[..]) else {
            debug!("server ignored connection request. failed to read connect token");
            return;
        };

        if !private_token.server_addresses.contains(&self.public_address) {
            debug!(
                "server ignored connection request. server address not in connect token whitelist"
            );
            return;
        }

        if self.find_client_index_by_address(from).is_some() {
            debug!(
                "server ignored connection request. a client with this address is already connected"
            );
            return;
        }

        if self.find_client_index_by_id(private_token.client_id).is_some() {
            debug!("server ignored connection request. a client with this id is already connected");
            return;
        }

        let mac: [u8; MAC_BYTES] =
            private_data[CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES..].try_into().unwrap();
        let connect_token_entry_index = match find_or_add_connect_token_entry(
            &mut self.connect_token_entries,
            from,
            &mac,
            expire_timestamp,
            current_timestamp,
            self.time,
        ) {
            ConnectTokenEntryResult::Accepted(index) => index,
            ConnectTokenEntryResult::Refused => {
                debug!("server ignored connection request. connect token has already been used");
                return;
            }
            ConnectTokenEntryResult::HistoryFull => {
                debug!("server ignored connection request. connect token history is full");
                return;
            }
        };

        if self.num_connected_clients == self.max_clients {
            debug!("server denied connection request. server is full");
            self.send_global_packet(&Packet::Denied, from, &private_token.server_to_client_key);
            return;
        }

        let expire_time = pending_mapping_expire_time(
            self.time,
            private_token.timeout_seconds,
            expire_timestamp,
            current_timestamp,
            self.max_connect_token_lifetime,
        );

        if !self.encryption_manager.add_encryption_mapping(
            from,
            &private_token.server_to_client_key,
            &private_token.client_to_server_key,
            self.time,
            expire_time,
            private_token.timeout_seconds,
            connect_token_entry_index,
        ) {
            debug!("server ignored connection request. failed to add encryption mapping");
            return;
        }

        let challenge_token = ChallengeToken {
            client_id: private_token.client_id,
            user_data: private_token.user_data,
        };
        let mut challenge_token_data = [0u8; CHALLENGE_TOKEN_BYTES];
        challenge_token.write(&mut challenge_token_data);
        if token::encrypt_challenge_token(
            &mut challenge_token_data,
            self.challenge_sequence,
            &self.challenge_key,
        )
        .is_err()
        {
            debug!("server ignored connection request. failed to encrypt challenge token");
            return;
        }

        let challenge_packet = Packet::Challenge {
            challenge_token_sequence: self.challenge_sequence,
            challenge_token_data,
        };
        self.challenge_sequence += 1;

        debug!("server sent connection challenge packet");
        self.send_global_packet(&challenge_packet, from, &private_token.server_to_client_key);
    }

    fn process_connection_response(
        &mut self,
        from: SocketAddr,
        challenge_token_sequence: u64,
        mut challenge_token_data: [u8; CHALLENGE_TOKEN_BYTES],
        encryption_index: Option<usize>,
    ) {
        if token::decrypt_challenge_token(
            &mut challenge_token_data,
            challenge_token_sequence,
            &self.challenge_key,
        )
        .is_err()
        {
            debug!("server ignored connection response. failed to decrypt challenge token");
            return;
        }

        let challenge_token = ChallengeToken::read(&challenge_token_data);

        let Some(encryption_index) = encryption_index else {
            debug!("server ignored connection response. no packet send key");
            return;
        };

        if self.find_client_index_by_address(from).is_some() {
            debug!(
                "server ignored connection response. a client with this address is already connected"
            );
            return;
        }

        if self.find_client_index_by_id(challenge_token.client_id).is_some() {
            debug!(
                "server ignored connection response. a client with this id is already connected"
            );
            return;
        }

        if self.num_connected_clients == self.max_clients {
            debug!("server denied connection response. server is full");
            let mut send_key = *self.encryption_manager.send_key(encryption_index);
            self.send_global_packet(&Packet::Denied, from, &send_key);
            send_key.zeroize();
            return;
        }

        let client_index = self.find_free_client_index().expect("server is not full");
        let timeout_seconds = self.encryption_manager.timeout(encryption_index);
        self.connect_client(
            client_index,
            from,
            challenge_token.client_id,
            encryption_index,
            timeout_seconds,
            &challenge_token.user_data,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_client(
        &mut self,
        client_index: usize,
        address: SocketAddr,
        client_id: u64,
        encryption_index: usize,
        timeout_seconds: i32,
        user_data: &UserData,
    ) {
        self.num_connected_clients += 1;
        debug_assert!(self.num_connected_clients <= self.max_clients);

        // the encryption mapping now belongs to a connected client: it no longer
        // expires on its own, only when the client disconnects
        self.encryption_manager.set_expire_time(encryption_index, -1.0);
        self.encryption_manager.set_client_index(encryption_index, Some(client_index));
        if let Some(connect_token_entry_index) =
            self.encryption_manager.connect_token_entry_index(encryption_index)
        {
            consume_connect_token_entry(&mut self.connect_token_entries, connect_token_entry_index);
        }

        let client = &mut self.clients[client_index];
        debug_assert!(!client.connected);
        client.connected = true;
        client.confirmed = false;
        client.client_id = client_id;
        client.timeout_seconds = timeout_seconds;
        client.encryption_index = Some(encryption_index);
        client.address = Some(address);
        client.sequence = 0;
        client.last_packet_send_time = self.time;
        client.last_packet_receive_time = self.time;
        client.user_data = *user_data;

        info!("server accepted client {address} {client_id:016x} in slot {client_index}");

        let packet = Packet::KeepAlive {
            client_index: client_index as u32,
            max_clients: self.max_clients as u32,
        };
        self.send_client_packet(&packet, client_index);

        self.push_event(ServerEvent::ClientConnected { client_index });
    }

    fn push_event(&mut self, event: ServerEvent) {
        if self.events.len() >= MAX_SERVER_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn disconnect_client_internal(
        &mut self,
        client_index: usize,
        send_disconnect_packets: bool,
        reason: DisconnectReason,
    ) {
        debug_assert!(self.running);
        debug_assert!(self.clients[client_index].connected);

        info!("server disconnected client {client_index}");

        self.push_event(ServerEvent::ClientDisconnected { client_index, reason });

        if send_disconnect_packets {
            debug!("server sent disconnect packets to client {client_index}");
            for _ in 0..NUM_DISCONNECT_PACKETS {
                self.send_client_packet(&Packet::Disconnect, client_index);
            }
        }

        self.clients[client_index].replay_protection.reset();

        if let Some(encryption_index) = self.clients[client_index].encryption_index {
            self.encryption_manager.set_client_index(encryption_index, None);
        }
        if let Some(address) = self.clients[client_index].address {
            self.encryption_manager.remove_encryption_mapping(address, self.time);
        }

        self.clients[client_index] = ClientSlot::new();
        self.num_connected_clients -= 1;
    }

    /// Sends a packet outside the context of a connected client (challenge and denied
    /// packets), using the server's global sequence number.
    fn send_global_packet(&mut self, packet: &Packet, to: SocketAddr, packet_key: &Key) {
        let mut packet_data = [0u8; MAX_PACKET_BYTES];
        let Ok(packet_bytes) = crate::packet::write_packet(
            packet,
            &mut packet_data,
            self.global_sequence,
            packet_key,
            self.protocol_id,
        ) else {
            return;
        };
        let _ = self.socket.send_to(&packet_data[..packet_bytes], to);
        self.global_sequence += 1;
    }

    fn send_client_packet(&mut self, packet: &Packet, client_index: usize) {
        let client = &self.clients[client_index];
        debug_assert!(client.connected);
        let (Some(encryption_index), Some(address)) = (client.encryption_index, client.address)
        else {
            return;
        };

        if !self.encryption_manager.touch(encryption_index, address, self.time) {
            error!("encryption mapping is out of date for client {client_index}");
            return;
        }

        let packet_key = self.encryption_manager.send_key(encryption_index);

        let mut packet_data = [0u8; MAX_PACKET_BYTES];
        let Ok(packet_bytes) = crate::packet::write_packet(
            packet,
            &mut packet_data,
            self.clients[client_index].sequence,
            packet_key,
            self.protocol_id,
        ) else {
            return;
        };
        let _ = self.socket.send_to(&packet_data[..packet_bytes], address);

        let client = &mut self.clients[client_index];
        client.sequence += 1;
        client.last_packet_send_time = self.time;
    }

    fn send_packets(&mut self) {
        if !self.running {
            return;
        }

        for client_index in 0..self.max_clients {
            let client = &self.clients[client_index];
            if client.connected
                && client.last_packet_send_time + 1.0 / PACKET_SEND_RATE <= self.time
            {
                debug!("server sent connection keep alive packet to client {client_index}");
                let packet = Packet::KeepAlive {
                    client_index: client_index as u32,
                    max_clients: self.max_clients as u32,
                };
                self.send_client_packet(&packet, client_index);
            }
        }
    }

    fn check_for_timeouts(&mut self) {
        if !self.running {
            return;
        }

        for client_index in 0..self.max_clients {
            let client = &self.clients[client_index];
            if client.connected
                && client.timeout_seconds > 0
                && client.last_packet_receive_time + client.timeout_seconds as f64 <= self.time
            {
                info!("server timed out client {client_index}");
                self.disconnect_client_internal(client_index, false, DisconnectReason::TimedOut);
            }
        }

        self.encryption_manager.remove_expired_mappings(self.time);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
        self.private_key.zeroize();
        self.challenge_key.zeroize();
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_connect_token_at(
    public_server_addresses: &[SocketAddr],
    internal_server_addresses: &[SocketAddr],
    create_timestamp: u64,
    expire_seconds: i32,
    timeout_seconds: i32,
    client_id: u64,
    protocol_id: u64,
    private_key: &Key,
    user_data: &UserData,
) -> Result<[u8; crate::CONNECT_TOKEN_BYTES], Error> {
    if public_server_addresses.is_empty()
        || public_server_addresses.len() > crate::MAX_SERVERS_PER_CONNECT
        || public_server_addresses.len() != internal_server_addresses.len()
    {
        return Err(Error::InvalidServerAddresses);
    }

    let expire_timestamp = if expire_seconds >= 0 {
        create_timestamp.saturating_add(expire_seconds as u64)
    } else {
        u64::MAX
    };

    let mut nonce = [0u8; token::CONNECT_TOKEN_NONCE_BYTES];
    crypto::random_bytes(&mut nonce);

    let private_token = PrivateConnectToken::generate(
        client_id,
        timeout_seconds,
        internal_server_addresses,
        user_data,
    );

    let mut private_data = Box::new([0u8; CONNECT_TOKEN_PRIVATE_BYTES]);
    private_token.write(&mut private_data);
    token::encrypt_connect_token_private(
        &mut private_data,
        protocol_id,
        expire_timestamp,
        &nonce,
        private_key,
    )?;

    let token = token::ConnectToken {
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

    let mut buffer = [0u8; crate::CONNECT_TOKEN_BYTES];
    token.write(&mut buffer);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    use crate::packet::{read_packet, write_packet};
    use crate::token::ConnectToken;
    use crate::{CONNECT_TOKEN_BYTES, Client, ClientState};

    const TEST_PROTOCOL_ID: u64 = 0x1122334455667788;
    // one second above the default maximum token lifetime, so a token generated just
    // after a server start expires strictly after the start floor rather than at it
    const TEST_TOKEN_EXPIRY: i32 = crate::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME + 1;
    const TEST_TOKEN_TIMEOUT: i32 = 5;
    const TEST_TIMESTAMP: u64 = 1_000_000;

    /// The server stamps its global packets (challenge and denied) with sequence
    /// numbers from the top half of the sequence space. Those packets are encrypted
    /// with the same per-connect-token server-to-client key as the packets sent to a
    /// connected client, whose sequence numbers start at zero, so a global sequence
    /// down in the bottom half repeats an AEAD nonce under a key that is already in
    /// use for the other half of the conversation. The reference C implementation
    /// seeded the global sequence when the server was created but zeroed it on stop,
    /// so a restarted server did exactly that (netcode commit dc21b70).
    const GLOBAL_SEQUENCE_FLOOR: u64 = u64::MAX / 2;

    fn test_address(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    /// Connection requests whose connect tokens have a negative timeout and which never
    /// complete the handshake must not hold their encryption mappings past the connect
    /// token's lifetime: once it has elapsed the mappings expire and the slots are reused.
    #[test]
    fn pending_mapping_expires_with_connect_token() {
        let mut manager = EncryptionManager::new();
        let time = 1000.0;
        let send_key = crypto::generate_key();
        let receive_key = crypto::generate_key();

        // every request arrives with two seconds left on its connect token
        let expire_timestamp = 1_700_000_030;
        let current_timestamp = expire_timestamp - 2;
        let expire_time =
            pending_mapping_expire_time(time, -1, expire_timestamp, current_timestamp, 30);

        for slot in 0..MAX_ENCRYPTION_MAPPINGS {
            let port = 10000 + slot as u16;
            assert!(manager.add_encryption_mapping(
                test_address(port),
                &send_key,
                &receive_key,
                time,
                expire_time,
                -1,
                0,
            ));
        }
        assert!(manager.find_encryption_mapping(test_address(10000), time).is_some());
        assert!(!manager.add_encryption_mapping(
            test_address(60000),
            &send_key,
            &receive_key,
            time,
            expire_time,
            -1,
            0,
        ));

        // the handshakes are never completed, so the mappings go with the connect token
        let after_token_expires = time + 3.0;
        assert!(
            manager.find_encryption_mapping(test_address(10000), after_token_expires).is_none()
        );
        assert!(manager.add_encryption_mapping(
            test_address(60000),
            &send_key,
            &receive_key,
            after_token_expires,
            after_token_expires + 5.0,
            5,
            0,
        ));

        assert_eq!(expire_time, time + 2.0);

        // a connect token that never expires is bounded by the maximum token lifetime
        assert_eq!(
            pending_mapping_expire_time(time, -1, u64::MAX, current_timestamp, 30),
            time + 30.0
        );
        assert_eq!(
            pending_mapping_expire_time(time, 5, expire_timestamp, current_timestamp, 30),
            time + 5.0
        );
    }

    #[test]
    fn encryption_manager_add_find_remove() {
        let mut manager = EncryptionManager::new();
        let time = 100.0;

        let send_key = crypto::generate_key();
        let receive_key = crypto::generate_key();

        for port in 0..5u16 {
            assert!(manager.add_encryption_mapping(
                test_address(40000 + port),
                &send_key,
                &receive_key,
                time,
                time + 5.0,
                5,
                0,
            ));
        }

        for port in 0..5u16 {
            let index = manager.find_encryption_mapping(test_address(40000 + port), time).unwrap();
            assert_eq!(*manager.send_key(index), send_key);
            assert_eq!(*manager.receive_key(index), receive_key);
        }
        assert!(manager.find_encryption_mapping(test_address(50000), time).is_none());

        assert!(manager.remove_encryption_mapping(test_address(40002), time));
        assert!(manager.find_encryption_mapping(test_address(40002), time).is_none());
        assert!(!manager.remove_encryption_mapping(test_address(40002), time));

        // entries expire after their timeout with no access
        assert!(manager.find_encryption_mapping(test_address(40000), time + 10.0).is_none());
    }

    #[test]
    fn encryption_manager_expire_time() {
        let mut manager = EncryptionManager::new();
        let send_key = crypto::generate_key();
        let receive_key = crypto::generate_key();

        // an entry that expires at time 105 unless a client connects
        assert!(manager.add_encryption_mapping(
            test_address(40000),
            &send_key,
            &receive_key,
            100.0,
            105.0,
            -1,
            0,
        ));
        assert!(manager.find_encryption_mapping(test_address(40000), 104.0).is_some());
        assert!(manager.find_encryption_mapping(test_address(40000), 106.0).is_none());
    }

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn encryption_entry_keys_are_zeroed_on_drop_and_reset() {
        // reset replaces every entry, which drops the old ones
        assert_zeroize_on_drop::<EncryptionEntry>();
    }

    #[test]
    fn encryption_manager_zeroes_keys_when_shrinking_past_expired_entries() {
        let mut manager = EncryptionManager::new();
        let send_key = crypto::generate_key();
        let receive_key = crypto::generate_key();

        // entry 0 times out after 5 seconds, entry 1 after 100
        assert!(manager.add_encryption_mapping(
            test_address(40000),
            &send_key,
            &receive_key,
            1000.0,
            -1.0,
            5,
            0,
        ));
        assert!(manager.add_encryption_mapping(
            test_address(40001),
            &send_key,
            &receive_key,
            1000.0,
            -1.0,
            100,
            1,
        ));

        // removing the last entry frees the expired entry before it as well
        assert!(manager.remove_encryption_mapping(test_address(40001), 1010.0));
        assert_eq!(manager.num_entries, 0);
        assert_eq!(manager.entries[0].send_key, [0; KEY_BYTES]);
        assert_eq!(manager.entries[0].receive_key, [0; KEY_BYTES]);
        assert_eq!(manager.entries[1].send_key, [0; KEY_BYTES]);
        assert_eq!(manager.entries[1].receive_key, [0; KEY_BYTES]);
    }

    #[test]
    fn encryption_manager_zeroes_keys_of_expired_mappings() {
        let mut manager = EncryptionManager::new();
        let send_key = crypto::generate_key();
        let receive_key = crypto::generate_key();

        assert!(manager.add_encryption_mapping(
            test_address(40000),
            &send_key,
            &receive_key,
            1000.0,
            1005.0,
            5,
            0,
        ));

        manager.remove_expired_mappings(1004.0);
        assert_eq!(*manager.send_key(0), send_key);
        assert_eq!(*manager.receive_key(0), receive_key);

        manager.remove_expired_mappings(1010.0);
        assert_eq!(manager.entries[0].address, None);
        assert_eq!(*manager.send_key(0), [0; KEY_BYTES]);
        assert_eq!(*manager.receive_key(0), [0; KEY_BYTES]);
    }

    #[test]
    fn encryption_manager_keeps_keys_of_connected_client_past_timeout() {
        let mut manager = EncryptionManager::new();
        let send_key = crypto::generate_key();
        let receive_key = crypto::generate_key();

        assert!(manager.add_encryption_mapping(
            test_address(40000),
            &send_key,
            &receive_key,
            1000.0,
            1005.0,
            5,
            0,
        ));
        manager.set_client_index(0, Some(0));

        manager.remove_expired_mappings(1010.0);
        assert_eq!(manager.entries[0].address, Some(test_address(40000)));
        assert_eq!(*manager.send_key(0), send_key);
        assert_eq!(*manager.receive_key(0), receive_key);
    }

    #[test]
    fn server_start_sets_configured_connect_token_restart_guard() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory_with_config(
            &network,
            test_address(0),
            TEST_PROTOCOL_ID,
            &private_key,
            ServerConfig { max_connect_token_lifetime: 60 },
            0.0,
        )
        .unwrap();

        assert_eq!(server.min_connect_token_expire_timestamp, 0);
        server.start_at(1, TEST_TIMESTAMP).unwrap();
        assert_eq!(server.min_connect_token_expire_timestamp, TEST_TIMESTAMP + 60);
    }

    #[test]
    fn connect_token_entries_enforce_single_use_and_bounded_history() {
        let mut entries = Vec::new();
        reset_connect_token_entries(&mut entries);

        let mac = [0x42u8; MAC_BYTES];

        // first use records the token
        let index = match find_or_add_connect_token_entry(
            &mut entries,
            test_address(40000),
            &mac,
            30,
            0,
            0.0,
        ) {
            ConnectTokenEntryResult::Accepted(index) => index,
            result => panic!("unexpected result: {result:?}"),
        };
        // a pending token can be retransmitted from the address that created it,
        // and the entry time is not refreshed
        assert_eq!(
            find_or_add_connect_token_entry(&mut entries, test_address(40000), &mac, 30, 1, 1.0,),
            ConnectTokenEntryResult::Accepted(index)
        );
        assert_eq!(entries[index].time, 0.0);
        // a pending token refuses every other address
        assert_eq!(
            find_or_add_connect_token_entry(&mut entries, test_address(40001), &mac, 30, 2, 2.0,),
            ConnectTokenEntryResult::Refused
        );

        // once the client is installed, the token is consumed and cannot be
        // presented again, including from the address that used it
        consume_connect_token_entry(&mut entries, index);
        assert_eq!(
            find_or_add_connect_token_entry(&mut entries, test_address(40000), &mac, 30, 3, 3.0,),
            ConnectTokenEntryResult::Refused
        );

        // a history whose entries all hold unexpired tokens refuses a new token
        // instead of evicting a consumed entry
        for i in 1..MAX_CONNECT_TOKEN_ENTRIES {
            let mut mac = [0u8; MAC_BYTES];
            mac[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(matches!(
                find_or_add_connect_token_entry(
                    &mut entries,
                    test_address(40000),
                    &mac,
                    30,
                    0,
                    4.0,
                ),
                ConnectTokenEntryResult::Accepted(_)
            ));
        }

        let new_mac = [0xFFu8; MAC_BYTES];
        assert_eq!(
            find_or_add_connect_token_entry(
                &mut entries,
                test_address(40000),
                &new_mac,
                30,
                0,
                5.0,
            ),
            ConnectTokenEntryResult::HistoryFull
        );

        // entries become reusable only after the token expires
        assert!(matches!(
            find_or_add_connect_token_entry(
                &mut entries,
                test_address(40000),
                &new_mac,
                30,
                30,
                6.0,
            ),
            ConnectTokenEntryResult::Accepted(_)
        ));
    }

    /// Sends `connect_token` to the server as a connection request from `socket` and
    /// returns the sequence number the server stamped on the challenge packet it sent
    /// back — that is, the AEAD nonce it used under this token's server-to-client key.
    fn challenge_sequence_on_the_wire(
        server: &mut Server,
        socket: &socket::MemorySocket,
        connect_token: &[u8; CONNECT_TOKEN_BYTES],
        time: &mut f64,
        timestamp: u64,
    ) -> u64 {
        let token = ConnectToken::read(connect_token).unwrap();
        let request = Packet::Request {
            protocol_id: token.protocol_id,
            expire_timestamp: token.expire_timestamp,
            nonce: token.nonce,
            private_data: token.private_data.clone(),
        };

        // connection request packets travel in the clear, so the write key is unused
        let mut request_data = [0u8; MAX_PACKET_BYTES];
        let request_bytes =
            write_packet(&request, &mut request_data, 0, &[0; KEY_BYTES], token.protocol_id)
                .unwrap();
        socket.send_to(&request_data[..request_bytes], server.address());

        let mut reply = [0u8; MAX_PACKET_BYTES];
        *time += 0.01;
        server.update_at(*time, timestamp);

        let (reply_bytes, _) = socket
            .recv_from(&mut reply)
            .expect("the server never replied to the connection request");
        let (packet, sequence) = read_packet(
            &mut reply[..reply_bytes],
            Some(&token.server_to_client_key),
            token.protocol_id,
            timestamp,
            None,
            AllowedPackets::CLIENT,
            None,
        )
        .expect("the server reply did not decrypt under the connect token key");
        assert!(matches!(packet, Packet::Challenge { .. }));
        sequence
    }

    /// Zero-length datagrams are valid UDP. One receive drain must read past any number
    /// of them and process the connection request queued behind them, rather than
    /// treating the first empty datagram as the end of the receive queue.
    #[test]
    fn one_receive_drain_processes_a_request_behind_empty_datagrams() {
        const EMPTY_DATAGRAMS: usize = 64;

        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server =
            Server::new_in_memory(&network, test_address(0), TEST_PROTOCOL_ID, &private_key, 0.0)
                .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let connect_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            0x1234,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        let token = ConnectToken::read(&connect_token).unwrap();
        let request = Packet::Request {
            protocol_id: token.protocol_id,
            expire_timestamp: token.expire_timestamp,
            nonce: token.nonce,
            private_data: token.private_data.clone(),
        };
        let mut request_data = [0u8; MAX_PACKET_BYTES];
        let request_bytes =
            write_packet(&request, &mut request_data, 0, &[0; KEY_BYTES], token.protocol_id)
                .unwrap();

        // the receive queue: EMPTY_DATAGRAMS empty datagrams, then the request, then nothing
        let client_address = test_address(40000);
        let mut queue: Vec<Option<usize>> = vec![Some(0); EMPTY_DATAGRAMS];
        queue.push(Some(request_bytes));
        queue.push(None);
        let mut queue = queue.into_iter();

        server.receive_packets_with(TEST_TIMESTAMP, |_, buffer| {
            socket::receive_packet_with(buffer, |buffer| match queue.next() {
                Some(Some(bytes)) => {
                    buffer[..bytes].copy_from_slice(&request_data[..bytes]);
                    Ok((bytes, client_address))
                }
                Some(None) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                None => panic!("read past the end of the receive queue"),
            })
        });

        assert!(queue.next().is_none(), "one receive drain did not reach the end of the queue");
        let time = server.time;
        assert!(
            server.encryption_manager.find_encryption_mapping(client_address, time).is_some(),
            "the connection request behind the empty datagrams was not processed"
        );
    }

    /// A server that is stopped and started again must not go back to stamping its
    /// global packets with sequence numbers a connected client's packets also use.
    #[test]
    fn restarted_server_keeps_global_packets_out_of_the_client_sequence_range() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        // the start floor is the start time plus this lifetime, one second under the
        // lifetime of the tokens minted below, so a token from the same second expires
        // strictly above the floor
        let mut server = Server::new_in_memory_with_config(
            &network,
            test_address(0),
            TEST_PROTOCOL_ID,
            &private_key,
            ServerConfig { max_connect_token_lifetime: TEST_TOKEN_EXPIRY - 1 },
            0.0,
        )
        .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let connect_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            0x1234,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        assert!(
            ConnectToken::read(&connect_token).unwrap().expire_timestamp
                > server.min_connect_token_expire_timestamp,
            "connect token expiry is above the server start floor"
        );

        let socket = network.bind(test_address(0));

        let mut time = 0.0;
        let before_restart = challenge_sequence_on_the_wire(
            &mut server,
            &socket,
            &connect_token,
            &mut time,
            TEST_TIMESTAMP,
        );
        assert!(before_restart > GLOBAL_SEQUENCE_FLOOR, "global sequence {before_restart}");

        server.stop();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let restarted_connect_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            0x1234,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        assert!(
            ConnectToken::read(&restarted_connect_token).unwrap().expire_timestamp
                > server.min_connect_token_expire_timestamp,
            "connect token expiry is above the server start floor"
        );

        let after_restart = challenge_sequence_on_the_wire(
            &mut server,
            &socket,
            &restarted_connect_token,
            &mut time,
            TEST_TIMESTAMP,
        );
        assert!(
            after_restart > GLOBAL_SEQUENCE_FLOOR,
            "a restarted server sent a global packet with sequence {after_restart}, which is in              the range used by packets to connected clients (client slot sequences restart at              {}), so the two share an AEAD nonce under the connect token key",
            server.clients[0].sequence,
        );
        assert_eq!(server.clients[0].sequence, 0, "client sequences start at zero after a start");
    }

    /// Every entry point that can leave the server ready to send global packets has to
    /// establish the floor itself, rather than inheriting it from another one — which
    /// is the whole of the upstream fix, since creation alone used to seed it.
    #[test]
    fn create_start_and_stop_each_reseed_the_global_sequence() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server =
            Server::new_in_memory(&network, test_address(0), TEST_PROTOCOL_ID, &private_key, 0.0)
                .unwrap();
        assert!(
            server.global_sequence > GLOBAL_SEQUENCE_FLOOR,
            "a new server starts below the global sequence floor: {}",
            server.global_sequence
        );

        // starting a stopped server whose sequence was left down in the client range
        server.global_sequence = 0;
        server.start_at(1, TEST_TIMESTAMP).unwrap();
        assert!(
            server.global_sequence > GLOBAL_SEQUENCE_FLOOR,
            "start did not reseed the global sequence: {}",
            server.global_sequence
        );

        // and stopping one, so that a later start cannot inherit a low sequence
        server.global_sequence = 0;
        server.stop();
        assert!(
            server.global_sequence > GLOBAL_SEQUENCE_FLOOR,
            "stop did not reseed the global sequence: {}",
            server.global_sequence
        );
    }

    /// Connects one in-memory client with `client_id` to `server`, advancing `time`.
    fn connect_in_memory_client(
        network: &socket::MemoryNetwork,
        server: &mut Server,
        private_key: &Key,
        client_id: u64,
        time: &mut f64,
    ) -> Client {
        let token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            client_id,
            TEST_PROTOCOL_ID,
            private_key,
            &[0x11; USER_DATA_BYTES],
        )
        .unwrap();
        let mut client = Client::new_in_memory(network, test_address(0), *time);
        client.connect(&token).unwrap();
        for _ in 0..10 {
            client.update_at(*time, TEST_TIMESTAMP);
            server.update_at(*time, TEST_TIMESTAMP);
            *time += 0.1;
        }
        assert_eq!(client.state(), ClientState::Connected);
        client
    }

    #[test]
    fn stop_clears_pending_events() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            test_address(40000),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        let mut time = 0.0;
        let _client = connect_in_memory_client(&network, &mut server, &private_key, 1, &mut time);
        assert_eq!(server.num_connected_clients(), 1);

        server.stop();
        server.start_at(1, TEST_TIMESTAMP).unwrap();
        assert_eq!(server.next_event(), None);
    }

    #[test]
    fn events_are_bounded_when_not_drained() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            test_address(40000),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(1, TEST_TIMESTAMP).unwrap();

        // each cycle queues a connect and a disconnect event
        let mut time = 0.0;
        let cycles = MAX_SERVER_EVENTS / 2 + 8;
        for client_id in 0..cycles as u64 {
            let _client =
                connect_in_memory_client(&network, &mut server, &private_key, client_id, &mut time);
            server.disconnect_client(0);
            assert!(server.events.len() <= MAX_SERVER_EVENTS);
        }
        assert_eq!(server.events.len(), MAX_SERVER_EVENTS);

        // the oldest events were dropped: the newest is the last disconnect
        assert_eq!(
            server.events.back(),
            Some(&ServerEvent::ClientDisconnected {
                client_index: 0,
                reason: DisconnectReason::ServerDisconnect,
            })
        );
        assert_eq!(server.next_event(), Some(ServerEvent::ClientConnected { client_index: 0 }));
    }

    #[test]
    fn in_memory_server_times_out_silent_client() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            test_address(40000),
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
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            1,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0x11; USER_DATA_BYTES],
        )
        .unwrap();

        let mut client = Client::new_in_memory(&network, test_address(0), 0.0);
        client.connect(&token).unwrap();

        let mut time = 0.0;
        for _ in 0..10 {
            client.update_at(time, TEST_TIMESTAMP);
            server.update_at(time, TEST_TIMESTAMP);
            time += 0.1;
        }
        assert_eq!(client.state(), ClientState::Connected);
        assert_eq!(server.num_connected_clients(), 1);
        assert_eq!(server.next_event(), Some(ServerEvent::ClientConnected { client_index: 0 }));

        // Client stops updating; advance server past TEST_TOKEN_TIMEOUT (5s).
        for _ in 0..60 {
            time += 0.1;
            server.update_at(time, TEST_TIMESTAMP + 6);
        }
        assert_eq!(server.num_connected_clients(), 0);
        assert_eq!(
            server.next_event(),
            Some(ServerEvent::ClientDisconnected {
                client_index: 0,
                reason: DisconnectReason::TimedOut,
            })
        );
    }

    #[test]
    fn in_memory_start_floor_and_token_expiry_boundaries() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory_with_config(
            &network,
            test_address(40000),
            TEST_PROTOCOL_ID,
            &private_key,
            ServerConfig { max_connect_token_lifetime: 30 },
            0.0,
        )
        .unwrap();
        server.start_at(2, TEST_TIMESTAMP).unwrap();
        assert_eq!(server.min_connect_token_expire_timestamp, TEST_TIMESTAMP + 30);

        // 1. Token whose expire_timestamp is 1 second below the floor (TEST_TIMESTAMP + 29) is rejected.
        let below_floor_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP - 1,
            30,
            TEST_TOKEN_TIMEOUT,
            1,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        let probe_socket = network.bind(test_address(0));
        let parsed = ConnectToken::read(&below_floor_token).unwrap();
        assert_eq!(parsed.expire_timestamp, TEST_TIMESTAMP + 29);
        let mut req_buf = [0u8; MAX_PACKET_BYTES];
        let req_len = write_packet(
            &Packet::Request {
                protocol_id: parsed.protocol_id,
                expire_timestamp: parsed.expire_timestamp,
                nonce: parsed.nonce,
                private_data: parsed.private_data.clone(),
            },
            &mut req_buf,
            0,
            &[0; KEY_BYTES],
            parsed.protocol_id,
        )
        .unwrap();
        probe_socket.send_to(&req_buf[..req_len], server.address());
        server.update_at(0.1, TEST_TIMESTAMP);
        let mut reply = [0u8; MAX_PACKET_BYTES];
        assert!(probe_socket.recv_from(&mut reply).is_none());

        // 2. Token just above the floor (expire_timestamp == TEST_TIMESTAMP + 31) presented after it
        // has expired (at current_timestamp == TEST_TIMESTAMP + 32) is rejected.
        let boundary_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            2,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        let parsed_boundary = ConnectToken::read(&boundary_token).unwrap();
        let req_len = write_packet(
            &Packet::Request {
                protocol_id: parsed_boundary.protocol_id,
                expire_timestamp: parsed_boundary.expire_timestamp,
                nonce: parsed_boundary.nonce,
                private_data: parsed_boundary.private_data.clone(),
            },
            &mut req_buf,
            0,
            &[0; KEY_BYTES],
            parsed_boundary.protocol_id,
        )
        .unwrap();
        probe_socket.send_to(&req_buf[..req_len], server.address());
        server.update_at(0.2, TEST_TIMESTAMP + 32);
        assert!(probe_socket.recv_from(&mut reply).is_none());

        // 3. The same token presented while valid (at TEST_TIMESTAMP + 10) receives a challenge.
        probe_socket.send_to(&req_buf[..req_len], server.address());
        server.update_at(0.3, TEST_TIMESTAMP + 10);
        assert!(probe_socket.recv_from(&mut reply).is_some());
    }

    #[test]
    fn in_memory_full_history_end_to_end_and_expiry_reuse() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            test_address(40000),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(4, TEST_TIMESTAMP).unwrap();

        let mut time = 0.0;
        let mut reply = [0u8; MAX_PACKET_BYTES];

        // Fill all 2048 connect token history entries via real request packets.
        for i in 0..MAX_CONNECT_TOKEN_ENTRIES {
            let token_bytes = generate_connect_token_at(
                &[server.address()],
                &[server.address()],
                TEST_TIMESTAMP,
                TEST_TOKEN_EXPIRY,
                TEST_TOKEN_TIMEOUT,
                (i + 1) as u64,
                TEST_PROTOCOL_ID,
                &private_key,
                &[0; USER_DATA_BYTES],
            )
            .unwrap();
            let parsed = ConnectToken::read(&token_bytes).unwrap();
            let sock = network.bind(test_address(0));
            let mut req_buf = [0u8; MAX_PACKET_BYTES];
            let req_len = write_packet(
                &Packet::Request {
                    protocol_id: parsed.protocol_id,
                    expire_timestamp: parsed.expire_timestamp,
                    nonce: parsed.nonce,
                    private_data: parsed.private_data.clone(),
                },
                &mut req_buf,
                0,
                &[0; KEY_BYTES],
                parsed.protocol_id,
            )
            .unwrap();
            sock.send_to(&req_buf[..req_len], server.address());
            time += 0.01;
            server.update_at(time, TEST_TIMESTAMP);
            assert!(sock.recv_from(&mut reply).is_some(), "entry {i} should receive a challenge");
        }

        // The 2049th token before expiry is refused because all 2048 entries are live.
        let extra_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP + 10,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            999_999,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        let mut client = Client::new_in_memory(&network, test_address(0), time);
        client.connect(&extra_token).unwrap();
        for _ in 0..5 {
            time += 0.1;
            client.update_at(time, TEST_TIMESTAMP + 10);
            server.update_at(time, TEST_TIMESTAMP + 10);
        }
        assert_eq!(client.state(), ClientState::SendingConnectionRequest);
        assert_eq!(server.num_connected_clients(), 0);

        // Once the wall clock advances to the first batch's expiry, those entries expire and
        // the client completes its connection.
        let first_batch_expiry = TEST_TIMESTAMP + TEST_TOKEN_EXPIRY as u64;
        for _ in 0..10 {
            time += 0.1;
            client.update_at(time, first_batch_expiry);
            server.update_at(time, first_batch_expiry);
        }
        assert_eq!(client.state(), ClientState::Connected);
        assert_eq!(server.num_connected_clients(), 1);
    }

    #[test]
    fn in_memory_256_clients_connect_and_257th_is_denied() {
        let network = socket::MemoryNetwork::new();
        let private_key = crypto::generate_key();
        let mut server = Server::new_in_memory(
            &network,
            test_address(40000),
            TEST_PROTOCOL_ID,
            &private_key,
            0.0,
        )
        .unwrap();
        server.start_at(MAX_CLIENTS, TEST_TIMESTAMP).unwrap();

        let mut time = 0.0;
        let mut clients = Vec::with_capacity(MAX_CLIENTS);
        for id in 0..MAX_CLIENTS {
            let token = generate_connect_token_at(
                &[server.address()],
                &[server.address()],
                TEST_TIMESTAMP,
                TEST_TOKEN_EXPIRY,
                TEST_TOKEN_TIMEOUT,
                id as u64 + 1,
                TEST_PROTOCOL_ID,
                &private_key,
                &[0; USER_DATA_BYTES],
            )
            .unwrap();
            let mut client = Client::new_in_memory(&network, test_address(0), time);
            client.connect(&token).unwrap();
            clients.push(client);
        }

        for _ in 0..6 {
            time += 0.1;
            for client in &mut clients {
                client.update_at(time, TEST_TIMESTAMP);
            }
            server.update_at(time, TEST_TIMESTAMP);
        }
        assert_eq!(server.num_connected_clients(), MAX_CLIENTS);
        assert!(clients.iter().all(|c| c.state() == ClientState::Connected));

        // 257th client is denied.
        let extra_token = generate_connect_token_at(
            &[server.address()],
            &[server.address()],
            TEST_TIMESTAMP,
            TEST_TOKEN_EXPIRY,
            TEST_TOKEN_TIMEOUT,
            9999,
            TEST_PROTOCOL_ID,
            &private_key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        let mut extra_client = Client::new_in_memory(&network, test_address(0), time);
        extra_client.connect(&extra_token).unwrap();
        for _ in 0..5 {
            time += 0.1;
            extra_client.update_at(time, TEST_TIMESTAMP);
            server.update_at(time, TEST_TIMESTAMP);
        }
        assert_eq!(extra_client.state(), ClientState::ConnectionDenied);
    }
}
