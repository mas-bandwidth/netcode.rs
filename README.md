# netcode.rs

[![CI](https://github.com/mas-bandwidth/netcode.rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mas-bandwidth/netcode.rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/netcode-official.svg)](https://crates.io/crates/netcode-official)
[![docs.rs](https://docs.rs/netcode-official/badge.svg)](https://docs.rs/netcode-official)

**netcode** is a secure client/server protocol for multiplayer games built on top of UDP.

This is a Rust implementation of the [netcode 1.02 standard](https://github.com/mas-bandwidth/netcode/blob/main/STANDARD.md). It is a from-scratch port of the [reference C implementation](https://github.com/mas-bandwidth/netcode), written in idiomatic Rust, and interoperates on the wire with other conforming implementations.

# Design

Real-time multiplayer games typically use UDP instead of TCP, because head of line blocking delays more recent packets while waiting for older dropped packets to be resent. The problem is that if you want to use UDP, it doesn't provide any concept of connection, so you have to build all this yourself, which is a lot of work!

**netcode** fixes this by providing a minimal and secure connection-oriented protocol on top of UDP, so you can quickly get to exchanging unreliable unordered packets and get busy building the rest of your game network protocol.

# Features

* Secure client connection with connect tokens. Only clients you authorize can connect to your server. This is _perfect_ for a game where you perform matchmaking in a web backend then send clients to connect to a server.
* Client slot system. Servers have n slots for clients. Clients are assigned to a slot when they connect to the server and are quickly denied connection if all slots are taken.
* Fast clean disconnect on client or server side of connection to quickly open up the slot for a new client, plus timeouts for hard disconnects.
* Encrypted and signed packets. Packets cannot be tampered with or read by parties not involved in the connection. Cryptography is performed by the pure Rust [RustCrypto](https://github.com/RustCrypto/AEADs) ChaCha20-Poly1305 implementation.
* Many security features including protection against maliciously crafted packets, packet replay attacks and packet amplification attacks.
* Support for both IPv4 and IPv6 connections.
* No unsafe code.

# Wire compatibility

This implementation is binary compatible with the reference C implementation, and that compatibility is enforced mechanically on every change:

* **Golden test vectors.** `tests/vectors/` holds every token and packet type as written by the reference C implementation from fixed inputs. The tests in `src/wire_compat.rs` assert this implementation produces byte-identical output — including AEAD ciphertext and authentication tags — and reads the C bytes back to the same values. They run in every `cargo test`.
* **Live interoperability.** CI builds the reference C implementation and runs `tests/c_interop.rs`: a C server accepting a connection from this client, and this server accepting a connection from the C client, each exchanging encrypted payloads in both directions for longer than the connect token timeout.

If either layer fails, the change breaks interoperability with other netcode implementations and must not merge.

# Usage

Add the crate to your project:

```console
cargo add netcode-official
```

The package is published as `netcode-official`; the library target is named `netcode`, so code says `use netcode::...` and will not need to change if the package later moves to the `netcode` name on crates.io.

Start by generating a random 32 byte private key. Do not share your private key with _anybody_.

Especially, **do not include your private key in your client executable!**

```rust
let private_key = netcode::generate_key();
```

Create a server with the private key and the public address clients connect to:

```rust
let server_address = "127.0.0.1:40000".parse().unwrap();

let mut server = netcode::Server::new(server_address, protocol_id, &private_key, time)
    .expect("failed to create server");
```

Then start the server with the number of client slots you want:

```rust
server.start(16).expect("failed to start server");
```

To connect a client, your client should hit a REST API to your backend that returns a _connect token_. Generate one with the same private key the server holds:

```rust
let connect_token = netcode::generate_connect_token(
    &[server_address],   // public server addresses the client connects to
    &[server_address],   // internal server addresses baked into the private token
    expire_seconds,
    timeout_seconds,
    client_id,
    protocol_id,
    &private_key,
    &user_data,
)?;
```

Using a connect token secures your server so that only clients authorized with your backend can connect:

```rust
let mut client = netcode::Client::new("0.0.0.0:0".parse().unwrap(), time)?;
client.connect(&connect_token)?;
```

Drive the client and server from your game loop, passing in the current time in seconds:

```rust
client.update(time);
server.update(time);
```

Once the client connects it is assigned a client index and can exchange encrypted and signed packets with the server:

```rust
if client.state() == netcode::ClientState::Connected {
    client.send_packet(&payload)?;
}

while let Some((payload, sequence)) = server.receive_packet(client_index) {
    // process payload
}
```

For more details please see [examples/client.rs](examples/client.rs), [examples/server.rs](examples/server.rs) and [examples/client_server.rs](examples/client_server.rs), which you can run with:

```console
cargo run --example client_server
```

# Source Code

This repository holds the implementation of netcode in Rust, ported from the [reference C implementation](https://github.com/mas-bandwidth/netcode).

Differences from the C implementation:

* Addresses are `std::net::SocketAddr` and errors are `Result`, so the parse/error-code APIs have no equivalent.
* Payloads are received as `Vec<u8>`, so there is no free-packet API.
* Server connect and disconnect callbacks are replaced by a polled event queue: `server.next_event()`.
* The network simulator, loopback clients, dual-stack servers and packet tagging are not (yet) ported.

If you'd like to create your own implementation of netcode, please read the [netcode 1.02 standard](https://github.com/mas-bandwidth/netcode/blob/main/STANDARD.md), and see [IMPLEMENTERS.md](https://github.com/mas-bandwidth/netcode/blob/main/IMPLEMENTERS.md) for findings other implementations should check themselves against. This implementation includes those fixes: the replay protection already-received test is written in the overflow-free subtraction form, and there is a regression test locking down the nonce construction.

# Development

```console
cargo test                                   # unit, wire-compatibility and integration tests
cargo fmt --check                            # formatting
cargo clippy --all-targets -- -D warnings    # lints
cargo +nightly fuzz run fuzz_read_packet     # coverage-guided fuzzing (cargo install cargo-fuzz)
```

CI runs the test suite on Linux, macOS and Windows (stable and beta Rust), checks formatting, clippy, rustdoc, the minimum supported Rust version (1.85), dependency licenses and security advisories with cargo-deny, live interoperability against the reference C implementation, and smoke-fuzzes the untrusted input surface with the harnesses in `fuzz/`.

To run the interoperability tests locally, build the [reference C implementation](https://github.com/mas-bandwidth/netcode) and point the tests at its example binaries:

```console
NETCODE_C_SERVER=path/to/netcode/build/bin/server \
NETCODE_C_CLIENT=path/to/netcode/build/bin/client \
cargo test --test c_interop -- --ignored --test-threads=1
```

# Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glenn-fiedler-11b735302/).

Other open source libraries by the same author include: [netcode](https://github.com/mas-bandwidth/netcode) (C reference implementation), [reliable](https://github.com/mas-bandwidth/reliable), [serialize](https://github.com/mas-bandwidth/serialize), and [yojimbo](https://github.com/mas-bandwidth/yojimbo).

If you find this software useful, [please consider sponsoring it](https://github.com/sponsors/mas-bandwidth). Thanks!

# License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).
