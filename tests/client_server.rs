//! Integration tests: a real client and server exchanging packets over localhost UDP.

use std::time::Duration;

use netcode::{Client, ClientState, DisconnectReason, Key, Server, ServerEvent};

const PROTOCOL_ID: u64 = 0x1122334455667788;
const CONNECT_TOKEN_EXPIRY: i32 = 30;
const CONNECT_TOKEN_TIMEOUT: i32 = 5;
const DELTA_TIME: f64 = 1.0 / 100.0;

struct Harness {
    private_key: Key,
    server: Server,
    clients: Vec<Client>,
    time: f64,
}

impl Harness {
    fn new(max_clients: usize) -> Self {
        // public port 0 binds an ephemeral port so parallel tests don't collide
        let private_key = netcode::generate_key();
        let mut server =
            Server::new("127.0.0.1:0".parse().unwrap(), PROTOCOL_ID, &private_key, 0.0).unwrap();
        server.start(max_clients).unwrap();
        Self { private_key, server, clients: Vec::new(), time: 0.0 }
    }

    /// Creates a client and starts connecting it with a freshly generated token.
    fn connect_client(&mut self, client_id: u64) -> usize {
        let mut client = Client::new("127.0.0.1:0".parse().unwrap(), self.time).unwrap();
        let connect_token = self.generate_connect_token(client_id);
        client.connect(&connect_token).unwrap();
        self.clients.push(client);
        self.clients.len() - 1
    }

    fn generate_connect_token(&self, client_id: u64) -> [u8; netcode::CONNECT_TOKEN_BYTES] {
        netcode::generate_connect_token(
            &[self.server.address()],
            &[self.server.address()],
            CONNECT_TOKEN_EXPIRY,
            CONNECT_TOKEN_TIMEOUT,
            client_id,
            PROTOCOL_ID,
            &self.private_key,
            &[0x42; netcode::USER_DATA_BYTES],
        )
        .unwrap()
    }

    fn update(&mut self) {
        for client in &mut self.clients {
            client.update(self.time);
        }
        self.server.update(self.time);
        std::thread::sleep(Duration::from_millis(1));
        self.time += DELTA_TIME;
    }

    /// Runs updates until the condition holds, panicking after `iterations` updates.
    fn run_until(&mut self, iterations: usize, mut done: impl FnMut(&mut Self) -> bool) {
        for _ in 0..iterations {
            if done(self) {
                return;
            }
            self.update();
        }
        let states: Vec<String> =
            self.clients.iter().map(|client| client.state().to_string()).collect();
        panic!(
            "condition not reached: client states are {:?}, {} clients connected to server",
            states,
            self.server.num_connected_clients()
        );
    }
}

#[test]
fn client_connects_to_server() {
    let mut harness = Harness::new(1);
    harness.connect_client(0x1234);

    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Connected);

    let client = &harness.clients[0];
    assert_eq!(client.client_index(), 0);
    assert_eq!(client.max_clients(), 1);
    assert_eq!(client.server_address(), Some(harness.server.address()));
    assert!(harness.server.client_connected(0));
    assert_eq!(harness.server.client_id(0), 0x1234);
    assert_eq!(harness.server.num_connected_clients(), 1);
    assert_eq!(harness.server.client_user_data(0), Some(&[0x42; netcode::USER_DATA_BYTES]));
    assert_eq!(harness.server.next_event(), Some(ServerEvent::ClientConnected { client_index: 0 }));
    assert_eq!(harness.server.next_event(), None);
}

#[test]
fn client_and_server_exchange_payload_packets() {
    let mut harness = Harness::new(1);
    harness.connect_client(0x1234);
    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Connected);

    let payload: Vec<u8> = (0..netcode::MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();

    let mut client_received = 0;
    let mut server_received = 0;

    let expected = payload.clone();
    harness.run_until(1000, |h| {
        h.clients[0].send_packet(&expected).unwrap();
        h.server.send_packet(0, &expected).unwrap();
        while let Some((packet, _sequence)) = h.clients[0].receive_packet() {
            assert_eq!(packet, expected);
            client_received += 1;
        }
        while let Some((packet, _sequence)) = h.server.receive_packet(0) {
            assert_eq!(packet, expected);
            server_received += 1;
        }
        client_received >= 10 && server_received >= 10
    });
}

#[test]
fn client_side_disconnect() {
    let mut harness = Harness::new(1);
    harness.connect_client(0x1234);
    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Connected);
    while harness.server.next_event().is_some() {}

    harness.clients[0].disconnect();
    assert_eq!(harness.clients[0].state(), ClientState::Disconnected);

    harness.run_until(1000, |h| h.server.num_connected_clients() == 0);
    assert_eq!(
        harness.server.next_event(),
        Some(ServerEvent::ClientDisconnected {
            client_index: 0,
            reason: DisconnectReason::ClientDisconnect
        })
    );
}

#[test]
fn server_side_disconnect() {
    let mut harness = Harness::new(1);
    harness.connect_client(0x1234);
    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Connected);

    harness.server.disconnect_client(0);
    assert!(!harness.server.client_connected(0));

    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Disconnected);
}

#[test]
fn server_full_denies_next_client() {
    let mut harness = Harness::new(1);
    harness.connect_client(1);
    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Connected);

    harness.connect_client(2);
    harness.run_until(1000, |h| h.clients[1].state() == ClientState::ConnectionDenied);
    assert_eq!(harness.server.num_connected_clients(), 1);
    assert_eq!(harness.clients[0].state(), ClientState::Connected);
}

#[test]
fn connect_token_cannot_be_reused_from_another_address() {
    let mut harness = Harness::new(2);
    let connect_token = harness.generate_connect_token(1);

    let mut client1 = Client::new("127.0.0.1:0".parse().unwrap(), 0.0).unwrap();
    client1.connect(&connect_token).unwrap();
    harness.clients.push(client1);
    harness.run_until(1000, |h| h.clients[0].state() == ClientState::Connected);

    // the same token sent from a different address must not connect
    let mut client2 = Client::new("127.0.0.1:0".parse().unwrap(), harness.time).unwrap();
    client2.connect(&connect_token).unwrap();
    harness.clients.push(client2);
    for _ in 0..300 {
        harness.update();
        assert_ne!(harness.clients[1].state(), ClientState::Connected);
    }
    assert_eq!(harness.server.num_connected_clients(), 1);
}

#[test]
fn wrong_protocol_id_cannot_connect() {
    let mut harness = Harness::new(1);

    let connect_token = netcode::generate_connect_token(
        &[harness.server.address()],
        &[harness.server.address()],
        CONNECT_TOKEN_EXPIRY,
        CONNECT_TOKEN_TIMEOUT,
        1,
        PROTOCOL_ID + 1,
        &harness.private_key,
        &[0u8; netcode::USER_DATA_BYTES],
    )
    .unwrap();

    let mut client = Client::new("127.0.0.1:0".parse().unwrap(), 0.0).unwrap();
    client.connect(&connect_token).unwrap();
    harness.clients.push(client);

    for _ in 0..300 {
        harness.update();
        assert_ne!(harness.clients[0].state(), ClientState::Connected);
    }
    assert_eq!(harness.server.num_connected_clients(), 0);
}

#[test]
fn wrong_private_key_cannot_connect() {
    let mut harness = Harness::new(1);

    let wrong_key = netcode::generate_key();
    let connect_token = netcode::generate_connect_token(
        &[harness.server.address()],
        &[harness.server.address()],
        CONNECT_TOKEN_EXPIRY,
        CONNECT_TOKEN_TIMEOUT,
        1,
        PROTOCOL_ID,
        &wrong_key,
        &[0u8; netcode::USER_DATA_BYTES],
    )
    .unwrap();

    let mut client = Client::new("127.0.0.1:0".parse().unwrap(), 0.0).unwrap();
    client.connect(&connect_token).unwrap();
    harness.clients.push(client);

    for _ in 0..300 {
        harness.update();
        assert_ne!(harness.clients[0].state(), ClientState::Connected);
    }
    assert_eq!(harness.server.num_connected_clients(), 0);
}

#[test]
fn multiple_clients_connect_and_exchange_packets() {
    const NUM_CLIENTS: usize = 4;

    let mut harness = Harness::new(NUM_CLIENTS);
    for client_id in 0..NUM_CLIENTS {
        harness.connect_client(client_id as u64 + 1);
    }

    harness.run_until(2000, |h| {
        h.clients.iter().all(|client| client.state() == ClientState::Connected)
    });
    assert_eq!(harness.server.num_connected_clients(), NUM_CLIENTS);

    // every client occupies a distinct slot and can talk to the server
    let mut received = [0usize; NUM_CLIENTS];
    harness.run_until(1000, |h| {
        for client in &mut h.clients {
            client.send_packet(&[client.client_index() as u8]).unwrap();
        }
        for (client_index, count) in received.iter_mut().enumerate() {
            while let Some((packet, _)) = h.server.receive_packet(client_index) {
                assert_eq!(packet, &[client_index as u8]);
                *count += 1;
            }
        }
        received.iter().all(|&count| count >= 5)
    });
}
