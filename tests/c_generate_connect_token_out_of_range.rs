//! Port of `test_generate_connect_token_out_of_range` from netcode.c (lines
//! 6293-6337 at mas-bandwidth/netcode@47a156b). The C entry point takes a
//! separate `num_server_addresses` int that this out-of-range test probes; the
//! Rust `generate_connect_token` takes `&[SocketAddr]` slices, so the int is
//! represented by the slice length.

use std::net::SocketAddr;

use netcode::{
    CONNECT_TOKEN_BYTES, KEY_BYTES, MAX_SERVERS_PER_CONNECT, USER_DATA_BYTES,
    generate_connect_token,
};

const TEST_PROTOCOL_ID: u64 = 0x1122334455667788;

#[test]
fn generate_connect_token_out_of_range() {
    let private_key = [0u8; KEY_BYTES];
    let user_data = [0u8; USER_DATA_BYTES];
    let server_address: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let client_id: u64 = 1000;

    let _ = CONNECT_TOKEN_BYTES;

    // num_server_addresses = 0 returns NETCODE_ERROR
    assert!(
        generate_connect_token(
            &[],
            &[],
            30,
            5,
            client_id,
            TEST_PROTOCOL_ID,
            &private_key,
            &user_data
        )
        .is_err()
    );

    // C: netcode_generate_connect_token(-1, ...) == NETCODE_ERROR -- no Rust equivalent: the Rust API takes &[SocketAddr] whose length is usize and cannot be negative

    // num_server_addresses = NETCODE_MAX_SERVERS_PER_CONNECT + 1 returns NETCODE_ERROR
    let too_many: Vec<SocketAddr> = vec![server_address; MAX_SERVERS_PER_CONNECT + 1];
    assert!(
        generate_connect_token(
            &too_many,
            &too_many,
            30,
            5,
            client_id,
            TEST_PROTOCOL_ID,
            &private_key,
            &user_data
        )
        .is_err()
    );

    // C: in a DEBUG build the paired netcode_assert calls fired first (test_oor_asserts_fired > 0) -- no Rust equivalent: the empty and too-many cases return InvalidServerAddresses before PrivateConnectToken::generate (whose debug_assert! is the analog) is reached, and there is no assert handler hook to observe it

    // C: netcode_set_assert_function(&netcode_default_assert_handler) -- no Rust equivalent: Rust has no assert-function hook

    // an in-range call still succeeds, so the guard cannot pass by rejecting everything
    let token = generate_connect_token(
        &[server_address],
        &[server_address],
        30,
        5,
        client_id,
        TEST_PROTOCOL_ID,
        &private_key,
        &user_data,
    );
    assert!(token.is_ok());
    assert_eq!(token.unwrap().len(), CONNECT_TOKEN_BYTES);
}
