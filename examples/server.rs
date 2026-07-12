//! A dedicated server listening on 127.0.0.1:40000 with 16 client slots. A port of
//! server.c from the reference implementation. Run alongside the client example.

use std::time::Duration;

use netcode::{Server, ServerEvent};

const PROTOCOL_ID: u64 = 0x1122334455667788;
const MAX_CLIENTS: usize = 16;

const PRIVATE_KEY: netcode::Key = [
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26, 0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
];

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut time = 0.0;
    let delta_time = 1.0 / 60.0;

    println!("[server]");

    let server_address = "127.0.0.1:40000".parse().unwrap();

    let mut server = Server::new(server_address, PROTOCOL_ID, &PRIVATE_KEY, time)
        .expect("failed to create server");

    server.start(MAX_CLIENTS).expect("failed to start server");

    let packet_data: Vec<u8> = (0..netcode::MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();

    loop {
        server.update(time);

        while let Some(event) = server.next_event() {
            match event {
                ServerEvent::ClientConnected { client_index } => {
                    println!(
                        "client {:016x} connected in slot {client_index}",
                        server.client_id(client_index)
                    );
                }
                ServerEvent::ClientDisconnected { client_index, reason } => {
                    println!("client in slot {client_index} disconnected ({reason:?})");
                }
            }
        }

        for client_index in 0..MAX_CLIENTS {
            if server.client_connected(client_index) {
                server.send_packet(client_index, &packet_data).unwrap();
                while server.receive_packet(client_index).is_some() {}
            }
        }

        std::thread::sleep(Duration::from_secs_f64(delta_time));
        time += delta_time;
    }
}
