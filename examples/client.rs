//! A client that connects to a server on 127.0.0.1:40000. A port of client.c from the
//! reference implementation. Run alongside the server example.
//!
//! In a real application the connect token comes from your web backend over HTTPS;
//! here it is generated locally with the shared test private key.

use std::time::Duration;

use netcode::{Client, ClientState};

const CONNECT_TOKEN_EXPIRY: i32 = 30;
const CONNECT_TOKEN_TIMEOUT: i32 = 5;
const PROTOCOL_ID: u64 = 0x1122334455667788;

const PRIVATE_KEY: netcode::Key = [
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26, 0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
];

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut time = 0.0;
    let delta_time = 1.0 / 60.0;

    println!("[client]");

    let server_address = "127.0.0.1:40000".parse().unwrap();

    let mut client =
        Client::new("0.0.0.0:0".parse().unwrap(), time).expect("failed to create client");

    let client_id = u64::from_le_bytes(netcode::generate_key()[..8].try_into().unwrap());
    println!("client id is {client_id:016x}");

    let connect_token = netcode::generate_connect_token(
        &[server_address],
        &[server_address],
        CONNECT_TOKEN_EXPIRY,
        CONNECT_TOKEN_TIMEOUT,
        client_id,
        PROTOCOL_ID,
        &PRIVATE_KEY,
        &[0u8; netcode::USER_DATA_BYTES],
    )
    .expect("failed to generate connect token");

    client.connect(&connect_token).expect("failed to connect");

    let packet_data: Vec<u8> = (0..netcode::MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();

    loop {
        client.update(time);

        if client.state() == ClientState::Connected {
            client.send_packet(&packet_data).unwrap();
            while client.receive_packet().is_some() {}
        }

        if client.state().is_error() {
            println!("client error state: {}", client.state());
            break;
        }

        std::thread::sleep(Duration::from_secs_f64(delta_time));
        time += delta_time;
    }
}
