//! Live interoperability tests against the reference C implementation.
//!
//! Ignored by default because they need the C example binaries from
//! https://github.com/mas-bandwidth/netcode. Build that repo with CMake, then:
//!
//! ```console
//! NETCODE_C_SERVER=path/to/build/bin/server \
//! NETCODE_C_CLIENT=path/to/build/bin/client \
//! cargo test --test c_interop -- --ignored --test-threads=1
//! ```
//!
//! Both sides use the C examples' conventions: protocol id 0x1122334455667788 and the
//! shared test private key. Each test picks a free loopback port at runtime and passes
//! it to the C example binary, so parallel interop runs never collide on a fixed port.
//! Each test keeps the connection alive for longer than the connect token timeout,
//! which proves packets decrypt in *both* directions: if either side's packets failed
//! to authenticate, the other side would time the connection out.

use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use netcode::{Client, ClientState, Server, ServerEvent};

const PROTOCOL_ID: u64 = 0x1122334455667788;

static INTEROP_LOCK: Mutex<()> = Mutex::new(());

/// Reserves a loopback address with a free ephemeral port. The socket is closed before
/// the address is used, so the C example binary can bind to it.
fn ephemeral_address() -> SocketAddr {
    let socket =
        UdpSocket::bind("127.0.0.1:0").expect("failed to reserve an ephemeral loopback port");
    socket.local_addr().expect("failed to read the reserved loopback address")
}

/// The address the C server is started on. An explicit `NETCODE_C_SERVER_ADDRESS` wins;
/// otherwise a free port is chosen when the test runs.
fn c_server_address() -> SocketAddr {
    match std::env::var("NETCODE_C_SERVER_ADDRESS") {
        Ok(value) => value.parse().expect("invalid NETCODE_C_SERVER_ADDRESS"),
        Err(_) => ephemeral_address(),
    }
}

const CONNECT_TOKEN_EXPIRY: i32 = netcode::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;
const CONNECT_TOKEN_TIMEOUT: i32 = 5;
const DELTA_TIME: f64 = 1.0 / 60.0;

/// How long to keep the connection alive: comfortably past the token timeout so a
/// one-directional crypto failure cannot go unnoticed.
const EXCHANGE_SECONDS: f64 = CONNECT_TOKEN_TIMEOUT as f64 + 2.0;

const PRIVATE_KEY: netcode::Key = [
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26, 0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
];

/// Waits until the wall clock second has advanced past the one this is called in. A
/// server refuses connect tokens issued in its start second, so tests call this after
/// starting a server and before a token is issued for it.
fn wait_for_next_second() {
    let unix_seconds = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let second = unix_seconds();
    while unix_seconds() <= second {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Whether a UDP socket is bound at `address`. Sends an empty datagram from a connected
/// socket: when nothing is bound there the OS reports the connection refused, and a bound
/// netcode server ignores the datagram, so the read times out.
fn udp_socket_is_bound(address: SocketAddr) -> bool {
    let local: SocketAddr =
        if address.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let probe = UdpSocket::bind(local).expect("failed to bind the probe socket");
    probe.connect(address).expect("failed to connect the probe socket");
    probe.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    if probe.send(&[]).is_err() {
        return false;
    }
    match probe.recv(&mut [0u8; 1]) {
        Err(error) => error.kind() != std::io::ErrorKind::ConnectionRefused,
        Ok(_) => true,
    }
}

/// Waits until the C server has bound its address. The C server example starts the
/// server directly after binding, so the start second is at or before the second this
/// returns in.
fn wait_for_c_server(address: SocketAddr) {
    let start = Instant::now();
    while !udp_socket_is_bound(address) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for the C server to bind {address}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Kills the C process when the test ends, pass or fail.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(env_var: &str, argument: String) -> ChildGuard {
    let binary = std::env::var(env_var)
        .unwrap_or_else(|_| panic!("set {env_var} to the path of the C example binary"));
    let child = Command::new(&binary)
        .arg(argument)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {binary}: {error}"));
    ChildGuard(child)
}

#[test]
#[ignore = "binds a real loopback socket; run with --ignored"]
fn ephemeral_address_is_free_and_on_loopback() {
    let address = ephemeral_address();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
}

#[test]
#[ignore = "binds a real loopback socket; run with --ignored"]
fn bind_probe_tells_a_bound_address_from_a_free_one() {
    let bound = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(udp_socket_is_bound(bound.local_addr().unwrap()));
    assert!(!udp_socket_is_bound(ephemeral_address()));
}

#[test]
#[ignore = "requires the C reference binaries; see the file docs"]
fn rust_client_connects_to_c_server() {
    let _guard = INTEROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let server_address = c_server_address();
    // the C server example takes the address to listen on
    let _c_server = spawn("NETCODE_C_SERVER", server_address.to_string());
    wait_for_c_server(server_address);
    wait_for_next_second();

    let mut client = Client::new("0.0.0.0:0".parse().unwrap(), 0.0).unwrap();

    let connect_token = netcode::generate_connect_token(
        &[server_address],
        &[server_address],
        CONNECT_TOKEN_EXPIRY,
        CONNECT_TOKEN_TIMEOUT,
        0x1234,
        PROTOCOL_ID,
        &PRIVATE_KEY,
        &[0u8; netcode::USER_DATA_BYTES],
    )
    .unwrap();

    client.connect(&connect_token).unwrap();

    // connect to the C server
    let start = Instant::now();
    let mut time = 0.0;
    while client.state() != ClientState::Connected {
        assert!(
            !client.state().is_error(),
            "client entered error state '{}' connecting to the C server",
            client.state()
        );
        assert!(start.elapsed() < Duration::from_secs(10), "timed out connecting to the C server");
        client.update(time);
        std::thread::sleep(Duration::from_secs_f64(DELTA_TIME));
        time += DELTA_TIME;
    }

    // exchange packets for longer than the token timeout
    let payload = [0x42u8; 100];
    let mut packets_received: u64 = 0;
    let exchange_end = time + EXCHANGE_SECONDS;
    while time < exchange_end {
        client.update(time);
        assert_eq!(
            client.state(),
            ClientState::Connected,
            "client lost connection to the C server during the exchange"
        );
        client.send_packet(&payload).unwrap();
        while let Some((packet, _sequence)) = client.receive_packet() {
            // the C server example sends 1200 byte packets of 0,1,2...
            assert_eq!(packet.len(), netcode::MAX_PAYLOAD_BYTES);
            assert!(packet.iter().enumerate().all(|(i, &byte)| byte == i as u8));
            packets_received += 1;
        }
        std::thread::sleep(Duration::from_secs_f64(DELTA_TIME));
        time += DELTA_TIME;
    }

    assert!(
        packets_received >= 60,
        "expected a steady stream of payload packets from the C server, got {packets_received}"
    );

    client.disconnect();
}

#[test]
#[ignore = "requires the C reference binaries; see the file docs"]
fn c_client_connects_to_rust_server() {
    let _guard = INTEROP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let server_address = ephemeral_address();
    let mut server = Server::new(server_address, PROTOCOL_ID, &PRIVATE_KEY, 0.0).unwrap();
    server.start(16).unwrap();
    // the C client example issues its token as it starts
    wait_for_next_second();

    // the C client example takes the server address to connect to
    let _c_client = spawn("NETCODE_C_CLIENT", server_address.to_string());

    // wait for the C client to connect
    let start = Instant::now();
    let mut time = 0.0;
    let client_index = loop {
        server.update(time);
        if let Some(ServerEvent::ClientConnected { client_index }) = server.next_event() {
            break client_index;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for the C client to connect"
        );
        std::thread::sleep(Duration::from_secs_f64(DELTA_TIME));
        time += DELTA_TIME;
    };

    // exchange packets for longer than the token timeout
    let payload = [0x42u8; 100];
    let mut packets_received: u64 = 0;
    let exchange_end = time + EXCHANGE_SECONDS;
    while time < exchange_end {
        server.update(time);
        assert!(
            server.client_connected(client_index),
            "the C client disconnected from the Rust server during the exchange"
        );
        server.send_packet(client_index, &payload).unwrap();
        while let Some((packet, _sequence)) = server.receive_packet(client_index) {
            // the C client example sends 1200 byte packets of 0,1,2...
            assert_eq!(packet.len(), netcode::MAX_PAYLOAD_BYTES);
            assert!(packet.iter().enumerate().all(|(i, &byte)| byte == i as u8));
            packets_received += 1;
        }
        std::thread::sleep(Duration::from_secs_f64(DELTA_TIME));
        time += DELTA_TIME;
    }

    assert!(
        packets_received >= 60,
        "expected a steady stream of payload packets from the C client, got {packets_received}"
    );

    server.disconnect_all_clients();
}
