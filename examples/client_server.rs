//! A client and server in one process, connecting over loopback UDP and exchanging
//! packets. A port of client_server.c from the reference implementation.

use std::time::Duration;

use netcode::{Client, ClientState, Server};

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

    println!("[client/server]");

    let server_address = "127.0.0.1:40000".parse().unwrap();

    let mut client =
        Client::new("0.0.0.0:0".parse().unwrap(), time).expect("failed to create client");

    let mut server = Server::new(server_address, PROTOCOL_ID, &PRIVATE_KEY, time)
        .expect("failed to create server");

    server.start(1).expect("failed to start server");

    let client_id = u64::from_le_bytes(netcode::generate_key()[..8].try_into().unwrap());
    println!("client id is {client_id:016x}");

    let mut user_data = [0u8; netcode::USER_DATA_BYTES];
    user_data[..8].copy_from_slice(&client_id.to_le_bytes());

    let connect_token = netcode::generate_connect_token(
        &[server_address],
        &[server_address],
        CONNECT_TOKEN_EXPIRY,
        CONNECT_TOKEN_TIMEOUT,
        client_id,
        PROTOCOL_ID,
        &PRIVATE_KEY,
        &user_data,
    )
    .expect("failed to generate connect token");

    client.connect(&connect_token).expect("failed to connect");

    let packet_data: Vec<u8> = (0..netcode::MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();

    let mut client_num_packets_received = 0;
    let mut server_num_packets_received = 0;

    loop {
        client.update(time);
        server.update(time);

        if client.state() == ClientState::Connected {
            client.send_packet(&packet_data).unwrap();
        }

        if server.client_connected(0) {
            server.send_packet(0, &packet_data).unwrap();
        }

        while let Some((packet, _sequence)) = client.receive_packet() {
            assert_eq!(packet, packet_data);
            client_num_packets_received += 1;
        }

        while let Some((packet, _sequence)) = server.receive_packet(0) {
            assert_eq!(packet, packet_data);
            server_num_packets_received += 1;
        }

        if client_num_packets_received >= 10
            && server_num_packets_received >= 10
            && server.client_connected(0)
        {
            println!("client and server successfully exchanged packets");
            server.disconnect_client(0);
        }

        if client.state().is_disconnected() {
            break;
        }

        std::thread::sleep(Duration::from_secs_f64(delta_time));
        time += delta_time;
    }
}
