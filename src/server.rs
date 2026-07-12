//! The netcode server.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use log::{debug, error, info};

use crate::packet::{AllowedPackets, Packet};
use crate::replay::ReplayProtection;
use crate::token::{
    self, ChallengeToken, PrivateConnectToken, CHALLENGE_TOKEN_BYTES, CONNECT_TOKEN_PRIVATE_BYTES,
};
use crate::{
    crypto, socket, Error, Key, UserData, KEY_BYTES, MAC_BYTES, MAX_CLIENTS, MAX_PACKET_BYTES,
    MAX_PAYLOAD_BYTES, NUM_DISCONNECT_PACKETS, PACKET_QUEUE_SIZE, PACKET_SEND_RATE,
    USER_DATA_BYTES,
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
    /// A client connected and was assigned the slot `client_index`.
    ClientConnected { client_index: usize },
    /// The client in slot `client_index` disconnected.
    ClientDisconnected { client_index: usize, reason: DisconnectReason },
}

// ----------------------------------------------------------------

const MAX_ENCRYPTION_MAPPINGS: usize = MAX_CLIENTS * 4;

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
            send_key: [0; KEY_BYTES],
            receive_key: [0; KEY_BYTES],
        }
    }

    fn expired(&self, time: f64) -> bool {
        (self.timeout_seconds > 0 && self.last_access_time + (self.timeout_seconds as f64) < time)
            || (self.expire_time >= 0.0 && self.expire_time < time)
    }
}

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
    ) -> bool {
        for index in 0..self.num_entries {
            let entry = &mut self.entries[index];
            if entry.address == Some(address) && !entry.expired(time) {
                entry.timeout_seconds = timeout_seconds;
                entry.expire_time = expire_time;
                entry.last_access_time = time;
                entry.send_key = *send_key;
                entry.receive_key = *receive_key;
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
                    self.entries[last - 1].address = None;
                    last -= 1;
                }
                self.num_entries = last;
            }

            return true;
        }

        false
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

    fn send_key(&self, index: usize) -> Key {
        self.entries[index].send_key
    }

    fn receive_key(&self, index: usize) -> Key {
        self.entries[index].receive_key
    }

    fn timeout(&self, index: usize) -> i32 {
        self.entries[index].timeout_seconds
    }
}

// ----------------------------------------------------------------

const MAX_CONNECT_TOKEN_ENTRIES: usize = MAX_CLIENTS * 8;

/// A history of connect tokens already used, keyed by token HMAC, so a token stolen
/// off the wire cannot be replayed from a different address.
struct ConnectTokenEntry {
    time: f64,
    mac: [u8; MAC_BYTES],
    address: Option<SocketAddr>,
}

fn reset_connect_token_entries(entries: &mut Vec<ConnectTokenEntry>) {
    entries.clear();
    entries.extend((0..MAX_CONNECT_TOKEN_ENTRIES).map(|_| ConnectTokenEntry {
        time: -1000.0,
        mac: [0; MAC_BYTES],
        address: None,
    }));
}

/// Returns whether the connect token may be used from this address: true for a token
/// never seen before (recording it) or one seen only from the same address.
fn find_or_add_connect_token_entry(
    entries: &mut [ConnectTokenEntry],
    address: SocketAddr,
    mac: &[u8; MAC_BYTES],
    time: f64,
) -> bool {
    // find the matching entry for the token mac and the oldest token entry.
    // constant time worst case. This is intentional!
    let mut matching_index = None;
    let mut oldest_index = 0;
    let mut oldest_time = f64::MAX;

    for (index, entry) in entries.iter().enumerate() {
        if &entry.mac == mac {
            matching_index = Some(index);
        }
        if entry.time < oldest_time {
            oldest_time = entry.time;
            oldest_index = index;
        }
    }

    match matching_index {
        // this is a new connect token: replace the oldest entry
        None => {
            entries[oldest_index] = ConnectTokenEntry { time, mac: *mac, address: Some(address) };
            true
        }
        // allow connect tokens we have already seen from the same address
        Some(index) => entries[index].address == Some(address),
    }
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
    socket: UdpSocket,
    public_address: SocketAddr,
    time: f64,
    running: bool,
    max_clients: usize,
    num_connected_clients: usize,
    global_sequence: u64,
    challenge_sequence: u64,
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
        let bind_address: SocketAddr = match public_address {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, public_address.port()).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, public_address.port()).into(),
        };
        let socket = socket::create_socket(bind_address)?;

        let mut public_address = public_address;
        if public_address.port() == 0 {
            public_address.set_port(socket.local_addr()?.port());
        }

        info!("server listening on {public_address}");

        let mut connect_token_entries = Vec::new();
        reset_connect_token_entries(&mut connect_token_entries);

        Ok(Self {
            protocol_id,
            private_key: *private_key,
            socket,
            public_address,
            time,
            running: false,
            max_clients: 0,
            num_connected_clients: 0,
            global_sequence: 1 << 63,
            challenge_sequence: 0,
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
        self.clients.clear();

        reset_connect_token_entries(&mut self.connect_token_entries);
        self.encryption_manager.reset();

        info!("server stopped");
    }

    /// Advances the server to the current time: receives and processes packets, sends
    /// keep-alives, and times out unresponsive clients.
    pub fn update(&mut self, time: f64) {
        self.time = time;
        self.receive_packets();
        self.send_packets();
        self.check_for_timeouts();
    }

    /// Pops the next connect or disconnect event.
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

    fn receive_packets(&mut self) {
        let current_timestamp = token::unix_timestamp();
        let mut packet_data = [0u8; MAX_PACKET_BYTES];
        while let Some((packet_bytes, from)) =
            socket::receive_packet(&self.socket, &mut packet_data)
        {
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
        let private_key = self.private_key;
        let replay_protection =
            client_index.map(|client_index| &mut self.clients[client_index].replay_protection);

        let Some((packet, sequence)) = crate::packet::read_packet(
            packet_data,
            read_packet_key.as_ref(),
            protocol_id,
            current_timestamp,
            Some(&private_key),
            AllowedPackets::SERVER,
            replay_protection,
        ) else {
            return;
        };

        self.process_packet(from, packet, sequence, encryption_index, client_index);
    }

    fn process_packet(
        &mut self,
        from: SocketAddr,
        packet: Packet,
        sequence: u64,
        encryption_index: Option<usize>,
        client_index: Option<usize>,
    ) {
        match packet {
            Packet::Request { private_data, .. } => {
                debug!("server received connection request from {from}");
                self.process_connection_request(from, &private_data);
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
            debug!("server ignored connection request. a client with this address is already connected");
            return;
        }

        if self.find_client_index_by_id(private_token.client_id).is_some() {
            debug!("server ignored connection request. a client with this id is already connected");
            return;
        }

        let mac: [u8; MAC_BYTES] =
            private_data[CONNECT_TOKEN_PRIVATE_BYTES - MAC_BYTES..].try_into().unwrap();
        if !find_or_add_connect_token_entry(&mut self.connect_token_entries, from, &mac, self.time)
        {
            debug!("server ignored connection request. connect token has already been used");
            return;
        }

        if self.num_connected_clients == self.max_clients {
            debug!("server denied connection request. server is full");
            self.send_global_packet(&Packet::Denied, from, &private_token.server_to_client_key);
            return;
        }

        let expire_time = if private_token.timeout_seconds >= 0 {
            self.time + private_token.timeout_seconds as f64
        } else {
            -1.0
        };

        if !self.encryption_manager.add_encryption_mapping(
            from,
            &private_token.server_to_client_key,
            &private_token.client_to_server_key,
            self.time,
            expire_time,
            private_token.timeout_seconds,
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
            debug!("server ignored connection response. a client with this address is already connected");
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
            let send_key = self.encryption_manager.send_key(encryption_index);
            self.send_global_packet(&Packet::Denied, from, &send_key);
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

        self.events.push_back(ServerEvent::ClientConnected { client_index });
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

        self.events.push_back(ServerEvent::ClientDisconnected { client_index, reason });

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
            &packet_key,
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
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
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
            ));
        }

        for port in 0..5u16 {
            let index = manager.find_encryption_mapping(test_address(40000 + port), time).unwrap();
            assert_eq!(manager.send_key(index), send_key);
            assert_eq!(manager.receive_key(index), receive_key);
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
        ));
        assert!(manager.find_encryption_mapping(test_address(40000), 104.0).is_some());
        assert!(manager.find_encryption_mapping(test_address(40000), 106.0).is_none());
    }

    #[test]
    fn connect_token_entries_reject_reuse_from_different_address() {
        let mut entries = Vec::new();
        reset_connect_token_entries(&mut entries);

        let mac = [0x42u8; MAC_BYTES];

        // first use records the token
        assert!(find_or_add_connect_token_entry(&mut entries, test_address(40000), &mac, 0.0));
        // same token from the same address is fine
        assert!(find_or_add_connect_token_entry(&mut entries, test_address(40000), &mac, 1.0));
        // same token from a different address is rejected
        assert!(!find_or_add_connect_token_entry(&mut entries, test_address(40001), &mac, 2.0));
    }
}
