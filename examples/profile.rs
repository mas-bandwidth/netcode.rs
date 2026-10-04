//! A profiling program: it fills every server slot and connects every client, then
//! exchanges full-size packets each iteration. A port of profile.c from the reference
//! implementation.

use std::io::Write;

use netcode::{Client, ClientState, Server, ServerConfig};

const MAX_SERVERS: usize = netcode::MAX_SERVERS_PER_CONNECT;
const MAX_CLIENTS: usize = MAX_SERVERS * netcode::MAX_CLIENTS;
const SERVER_BASE_PORT: u16 = 40000;
const CONNECT_TOKEN_EXPIRY: i32 = 45;
const CONNECT_TOKEN_TIMEOUT: i32 = 5;
const PROTOCOL_ID: u64 = 0x1122334455667788;

fn random_bytes(buffer: &mut [u8]) {
    getrandom::fill(buffer).expect("the operating system random number generator failed");
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn random_int(rng: &mut Rng, a: i32, b: i32) -> i32 {
    assert!(a < b);
    let result = a + (rng.next() % (b - a + 1) as u64) as i32;
    assert!(result >= a);
    assert!(result <= b);
    result
}

fn main() {
    let mut num_iterations: i64 = 100;

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        num_iterations = args[1].parse().unwrap_or(0);
    }

    println!("initializing");

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut rng =
        Rng::new(getrandom::u64().expect("the operating system random number generator failed"));

    let private_key = netcode::generate_key();
    let packet_data: Vec<u8> = (0..netcode::MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();

    let server_config = ServerConfig { max_connect_token_lifetime: CONNECT_TOKEN_EXPIRY };

    let mut server: [Option<Server>; MAX_SERVERS] = std::array::from_fn(|_| None);
    for (i, entry) in server.iter_mut().enumerate() {
        let server_address = format!("127.0.0.1:{}", SERVER_BASE_PORT + i as u16).parse().unwrap();
        *entry = Some(
            Server::new_with_config(server_address, PROTOCOL_ID, &private_key, server_config, 0.0)
                .unwrap(),
        );
    }

    let mut client: Vec<Option<Client>> = (0..MAX_CLIENTS).map(|_| None).collect();
    for entry in client.iter_mut() {
        *entry = Some(Client::new("0.0.0.0:0".parse().unwrap(), 0.0).unwrap());
    }

    print!("profiling");
    let _ = std::io::stdout().flush();

    let mut time = 0.0;
    let delta_time = 0.1;

    if num_iterations > 0 {
        for _ in 0..num_iterations {
            profile_iteration(&mut rng, time, &private_key, &packet_data, &mut server, &mut client);

            time += delta_time;
        }
    }

    #[allow(clippy::print_with_newline)]
    print!("shutdown\n");

    for entry in server.iter_mut() {
        *entry = None;
    }

    for entry in client.iter_mut() {
        *entry = None;
    }
}

#[allow(clippy::too_many_arguments)]
fn profile_iteration(
    rng: &mut Rng,
    time: f64,
    private_key: &netcode::Key,
    packet_data: &[u8],
    server: &mut [Option<Server>; MAX_SERVERS],
    client: &mut [Option<Client>],
) {
    print!(".");
    let _ = std::io::stdout().flush();

    for s in server.iter_mut().flatten() {
        if !s.running() {
            s.start(random_int(rng, 1, netcode::MAX_CLIENTS as i32) as usize).unwrap();
        }

        if s.running() {
            let max_clients = s.max_clients();
            for client_index in 0..max_clients {
                if s.client_connected(client_index) {
                    s.send_packet(client_index, packet_data).unwrap();
                }
            }

            for client_index in 0..max_clients {
                if s.client_connected(client_index) {
                    while let Some((packet, _sequence)) = s.receive_packet(client_index) {
                        assert_eq!(packet, packet_data);
                    }
                }
            }
        }

        s.update(time);
    }

    for c in client.iter_mut().flatten() {
        if c.state() as u8 <= ClientState::Disconnected as u8 {
            let mut client_id_bytes = [0u8; 8];
            random_bytes(&mut client_id_bytes);
            let client_id = u64::from_le_bytes(client_id_bytes);

            let mut user_data = [0u8; netcode::USER_DATA_BYTES];
            random_bytes(&mut user_data);

            let mut server_addresses = Vec::new();
            for (j, s) in server.iter().enumerate() {
                if server_addresses.len() == netcode::MAX_SERVERS_PER_CONNECT {
                    break;
                }

                if let Some(s) = s {
                    if s.running() {
                        server_addresses.push(
                            format!("127.0.0.1:{}", SERVER_BASE_PORT + j as u16).parse().unwrap(),
                        );
                    }
                }
            }

            if !server_addresses.is_empty() {
                if let Ok(connect_token) = netcode::generate_connect_token(
                    &server_addresses,
                    &server_addresses,
                    CONNECT_TOKEN_EXPIRY,
                    CONNECT_TOKEN_TIMEOUT,
                    client_id,
                    PROTOCOL_ID,
                    private_key,
                    &user_data,
                ) {
                    c.connect(&connect_token).unwrap();
                }
            }
        }

        if c.state() == ClientState::Connected {
            c.send_packet(packet_data).unwrap();

            while let Some((packet, _sequence)) = c.receive_packet() {
                assert_eq!(packet, packet_data);
            }
        }

        c.update(time);
    }
}
