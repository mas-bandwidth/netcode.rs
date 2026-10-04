//! A soak test: it randomly creates and destroys servers and clients and exchanges
//! traffic. A port of soak.c from the reference implementation.

use std::sync::atomic::{AtomicBool, Ordering};

use netcode::{Client, ClientState, Server, ServerConfig};

const MAX_SERVERS: usize = 2;
const MAX_CLIENTS: usize = 64;
const SERVER_BASE_PORT: u16 = 20000;
const CONNECT_TOKEN_EXPIRY: i32 = 45;
const CONNECT_TOKEN_TIMEOUT: i32 = 5;
const PROTOCOL_ID: u64 = 0x1122334455667788;

static QUIT: AtomicBool = AtomicBool::new(false);

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

fn random_float(rng: &mut Rng, a: f32, b: f32) -> f32 {
    assert!(a < b);
    let random = rng.next() as f32 / u64::MAX as f32;
    let diff = b - a;
    let r = random * diff;
    a + r
}

fn main() {
    let mut num_iterations: i64 = -1;

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        num_iterations = args[1].parse().unwrap_or(0);
    }

    println!("[soak]\nnum_iterations = {num_iterations}");

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut rng =
        Rng::new(getrandom::u64().expect("the operating system random number generator failed"));

    let private_key = netcode::generate_key();
    let packet_data: Vec<u8> = (0..netcode::MAX_PAYLOAD_BYTES).map(|i| i as u8).collect();

    let mut server: [Option<Server>; MAX_SERVERS] = std::array::from_fn(|_| None);
    let mut client: [Option<Client>; MAX_CLIENTS] = std::array::from_fn(|_| None);

    let mut time = 0.0;
    let delta_time = 0.1;

    if num_iterations > 0 {
        for _ in 0..num_iterations {
            if QUIT.load(Ordering::Relaxed) {
                break;
            }

            soak_iteration(&mut rng, time, &private_key, &packet_data, &mut server, &mut client);

            time += delta_time;
        }
    } else {
        while !QUIT.load(Ordering::Relaxed) {
            soak_iteration(&mut rng, time, &private_key, &packet_data, &mut server, &mut client);

            time += delta_time;
        }
    }

    println!("shutdown");

    for entry in server.iter_mut() {
        *entry = None;
    }

    for entry in client.iter_mut() {
        *entry = None;
    }

    let _ = random_float(&mut rng, 0.0, 1.0);
}

#[allow(clippy::too_many_arguments, clippy::needless_range_loop)]
fn soak_iteration(
    rng: &mut Rng,
    time: f64,
    private_key: &netcode::Key,
    packet_data: &[u8],
    server: &mut [Option<Server>; MAX_SERVERS],
    client: &mut [Option<Client>; MAX_CLIENTS],
) {
    let server_config = ServerConfig { max_connect_token_lifetime: CONNECT_TOKEN_EXPIRY };

    for i in 0..MAX_SERVERS {
        if server[i].is_none() && random_int(rng, 0, 10) == 0 {
            let server_address =
                format!("127.0.0.1:{}", SERVER_BASE_PORT + i as u16).parse().unwrap();

            server[i] = Some(
                Server::new_with_config(
                    server_address,
                    PROTOCOL_ID,
                    private_key,
                    server_config,
                    time,
                )
                .unwrap(),
            );

            println!("created server {:p}", server[i].as_ref().unwrap());
        }

        if let Some(s) = server[i].as_ref() {
            if s.num_connected_clients() == s.max_clients() && random_int(rng, 0, 10000) == 0 {
                println!("destroy server {:p}", s);
                server[i] = None;
            }
        }
    }

    for i in 0..MAX_CLIENTS {
        if client[i].is_none() && random_int(rng, 0, 10) == 0 {
            match Client::new("0.0.0.0:0".parse().unwrap(), time) {
                Ok(c) => {
                    println!("created client {i}: {:p}", &c);
                    client[i] = Some(c);
                }
                Err(_) => {
                    println!("failed to create client");
                    std::process::exit(1);
                }
            }
        }

        if let Some(c) = client[i].as_ref() {
            if random_int(rng, 0, 1000) == 0 {
                println!("destroy client {i}: {c:p}");
                client[i] = None;
            }
        }
    }

    for i in 0..MAX_SERVERS {
        let Some(s) = server[i].as_mut() else {
            continue;
        };

        if random_int(rng, 0, 10) == 0 && !s.running() {
            s.start(random_int(rng, 1, netcode::MAX_CLIENTS as i32) as usize).unwrap();
        }

        if random_int(rng, 0, 1000) == 0
            && s.num_connected_clients() == s.max_clients()
            && s.running()
        {
            s.stop();
        }

        if s.running() {
            let max_clients = s.max_clients();
            for client_index in 0..max_clients {
                if s.client_connected(client_index) {
                    let len = random_int(rng, 1, netcode::MAX_PAYLOAD_BYTES as i32) as usize;
                    s.send_packet(client_index, &packet_data[..len]).unwrap();
                }
            }

            for client_index in 0..max_clients {
                if s.client_connected(client_index) {
                    while let Some((packet, _sequence)) = s.receive_packet(client_index) {
                        assert_eq!(packet, packet_data[..packet.len()]);
                    }
                }
            }
        }

        s.update(time);
    }

    for i in 0..MAX_CLIENTS {
        let Some(c) = client[i].as_mut() else {
            continue;
        };

        if random_int(rng, 0, 10) == 0 && c.state() as u8 <= ClientState::Disconnected as u8 {
            let mut client_id_bytes = [0u8; 8];
            random_bytes(&mut client_id_bytes);
            let client_id = u64::from_le_bytes(client_id_bytes);

            let mut user_data = [0u8; netcode::USER_DATA_BYTES];
            random_bytes(&mut user_data);

            let mut server_addresses = Vec::new();
            for j in 0..MAX_SERVERS {
                if server_addresses.len() == netcode::MAX_SERVERS_PER_CONNECT {
                    break;
                }

                if let Some(s) = server[j].as_ref() {
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

        if random_int(rng, 0, 100) == 0 && c.state() == ClientState::Connected {
            c.disconnect();
        }

        if c.state() == ClientState::Connected {
            let len = random_int(rng, 1, netcode::MAX_PAYLOAD_BYTES as i32) as usize;
            c.send_packet(&packet_data[..len]).unwrap();

            while let Some((packet, _sequence)) = c.receive_packet() {
                assert_eq!(packet, packet_data[..packet.len()]);
            }
        }

        c.update(time);
    }
}
