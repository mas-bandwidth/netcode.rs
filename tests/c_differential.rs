//! Differential test against the reference C implementation for the per-update
//! receive drain.
//!
//! Feeds the same scripted receive queues through the C reference and through
//! this port, then compares the two transcripts exactly, line by line, not by
//! shape. The C side (`tests/c/oracle.c`) installs `receive_packet_override`
//! and calls `netcode_server_receive_packets` / `netcode_client_receive_packets`
//! for one update; the port side is `netcode::differential_transcript`.
//!
//! This is a functional test: it builds and runs a local C program on fixed
//! inputs with no socket and no clock anywhere in the comparison. It is
//! `#[ignore = "functional"]` so the unit gate stays hermetic. The functional
//! run fails, it does not pass, when `NETCODE_C_DIR` is unset: a skip that
//! returns is counted as a pass by libtest.
//!
//! ```console
//! NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1
//! ```
//!
//! `NETCODE_C_DIR` must be a checkout of mas-bandwidth/netcode holding the fix
//! (branch `sprint/netcode-audit-fixes` at or after `7cd5f513`).

use std::path::PathBuf;
use std::process::Command;

/// Resolves `NETCODE_C_DIR` for a functional (`#[ignore = "functional"]`) test.
///
/// Unset is a failure. Returning early would let libtest count the functional
/// run as a pass when no C reference was compared.
fn require_netcode_c_dir(scenario: &str) -> String {
    std::env::var("NETCODE_C_DIR").unwrap_or_else(|_| {
        panic!(
            "c_differential ({scenario}): NETCODE_C_DIR is unset under the functional tag; \
             this test fails rather than passing. Set it to a checkout of mas-bandwidth/netcode \
             holding the fix, then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        )
    })
}

/// Builds and runs the C oracle, returning its stdout split into lines.
///
/// The oracle is `tests/c/oracle.c` beside this file. It `#include`s netcode.c,
/// so netcode.c is not passed on the command line. `-finstrument-functions` is
/// how the oracle counts entries into the reference's packet processor; without
/// it those counts stay zero and the transcripts cannot match.
fn c_transcript(netcode_c_dir: &str) -> Vec<String> {
    c_transcript_for(netcode_c_dir, &[])
}

/// Like [`c_transcript`], but passes `args` to the oracle so one program can
/// serve more than one differential scenario, one transcript per invocation
/// (`["challenge"]` for the challenge-token binding scenario, `["disconnect"]`
/// for the disconnect-callback re-entry scenario).
fn c_transcript_for(netcode_c_dir: &str, args: &[&str]) -> Vec<String> {
    c_transcript_cc(netcode_c_dir, args, &[])
}

/// Like [`c_transcript_for`], but passes extra flags to `cc`. The global-nonce
/// scenario is built with `-DNETCODE_ORACLE_GLOBAL_NONCE` so the oracle compiles
/// only that scenario against the reference.
fn c_transcript_cc(netcode_c_dir: &str, args: &[&str], extra_cc: &[&str]) -> Vec<String> {
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/c/oracle.c");
    let out_dir = std::env::temp_dir().join("netcode-c-differential");
    std::fs::create_dir_all(&out_dir).expect("create temp build dir");
    let binary = out_dir.join("oracle");

    let status = Command::new("cc")
        .args(["-O2", "-ffp-contract=off", "-finstrument-functions"])
        .args(extra_cc)
        .arg(format!("-I{netcode_c_dir}"))
        .arg(format!("-I{netcode_c_dir}/sodium"))
        .arg(&oracle)
        .arg(format!("{netcode_c_dir}/sodium/sodium.c"))
        .arg("-lm")
        .arg("-o")
        .arg(&binary)
        .status()
        .expect("failed to run cc; is a C compiler installed?");
    assert!(status.success(), "failed to build the C oracle");

    let output = Command::new(&binary).args(args).output().expect("failed to run the C oracle");
    assert!(output.status.success(), "the C oracle exited with a failure");
    let stdout = String::from_utf8(output.stdout).expect("the C oracle wrote non-UTF-8 output");
    stdout.lines().map(str::to_string).collect()
}

#[test]
#[ignore = "functional"]
fn receive_drain_matches_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("receive_drain");

    let c_lines = c_transcript(&netcode_c_dir);
    let port_lines = netcode::differential_transcript();

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port transcripts first differ at line {index}: C {c_line:?} vs port {port_line:?}"
        );
    }
}

#[test]
#[ignore = "functional"]
fn challenge_token_binds_matches_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("challenge");

    let c_lines = c_transcript_for(&netcode_c_dir, &["challenge"]);
    let port_lines = netcode::challenge_token_transcript();

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port challenge transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port challenge transcripts first differ at line {index}: C {c_line:?} vs port {port_line:?}"
        );
    }
}

/// The three disconnect paths the reference C fix (netcode PR 196) makes
/// re-entry-safe, over one server with one admitted client: the application
/// disconnects the client while the callback disconnects it again; the
/// application stops the server from inside the callback and a restart finds
/// every slot empty; a timeout inside update whose callback stops the server.
/// The C oracle re-enters the way the C test does; the port side
/// `netcode::differential_disconnect_transcript` has no callback at all, so the
/// comparison is over the observable contract both must print.
#[test]
#[ignore = "functional"]
fn disconnect_paths_match_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("disconnect");

    let c_lines = c_transcript_for(&netcode_c_dir, &["disconnect"]);
    let port_lines = netcode::differential_disconnect_transcript();

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port disconnect transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port disconnect transcripts first differ at line {index}: \
             C {c_line:?} vs port {port_line:?}"
        );
    }
}

/// The replay top-sequence and restart-floor edges, fed through the C reference
/// and through this port and compared line by line, not by shape. The C oracle
/// (`["replay"]`) drives the reference's file-local replay protection and packet
/// read with explicit timestamps; the port half is
/// `netcode::replay_transcript`. Each line is
/// `<op> <sequence or expire> -> <0|1|accepted|refused>` in decimal.
#[test]
#[ignore = "functional"]
fn replay_edges_match_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("replay");

    let c_lines = c_transcript_for(&netcode_c_dir, &["replay"]);
    let port_lines = netcode::replay_transcript();

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port replay transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port replay transcripts first differ at line {index}: \
             C {c_line:?} vs port {port_line:?}"
        );
    }
}

/// The pre-connect mapping lifetime and the never-expiring token refusal the
/// reference C fix bounds, fed through the C reference and through this port and
/// compared line by line, not by shape. The C oracle (`["lifetime"]`) drives the
/// reference's pre-connect mapping and packet read with explicit timestamps; the
/// port half is `netcode::token_lifetime_transcript`. Each line is
/// `preconnect <timeout> -> <offset|never>`,
/// `preconnect-response <timeout> -> <connects|refused>`, or
/// `request <expire> -> <accepted|refused>`.
#[test]
#[ignore = "functional"]
fn token_lifetimes_match_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("lifetime");

    let c_lines = c_transcript_for(&netcode_c_dir, &["lifetime"]);
    let port_lines = netcode::token_lifetime_transcript();

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port lifetime transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port lifetime transcripts first differ at line {index}: \
             C {c_line:?} vs port {port_line:?}"
        );
    }
}

/// Builds the port half of the address-family refusal transcript with the public
/// client API: an IPv4-only client (`Client::new` on 127.0.0.1) is fed three
/// connect tokens whose server address lists are [[::1]:40000],
/// [[::1]:40000, 127.0.0.1:40000] and [127.0.0.1]:40000]. One line per token:
/// `<label> state <state> address <index|none>`.
fn connect_family_transcript() -> Vec<String> {
    use std::net::SocketAddr;

    let key = netcode::generate_key();
    let protocol_id = 0x1122334455667788u64;
    let cases: [(&str, &[&str]); 3] = [
        ("ipv6-only", &["[::1]:40000"]),
        ("ipv6-then-ipv4", &["[::1]:40000", "127.0.0.1:40000"]),
        ("ipv4-only", &["127.0.0.1:40000"]),
    ];

    let mut lines = Vec::new();
    for (label, addresses) in cases {
        let addrs: Vec<SocketAddr> = addresses.iter().map(|a| a.parse().unwrap()).collect();
        let mut client = netcode::Client::new("127.0.0.1:0".parse().unwrap(), 0.0).unwrap();
        let token = netcode::generate_connect_token(
            &addrs,
            &addrs,
            30,
            10,
            1,
            protocol_id,
            &key,
            &[0u8; netcode::USER_DATA_BYTES],
        )
        .unwrap();

        let _ = client.connect(&token);

        let state = client.state().to_string().replace(' ', "_");
        let index =
            client.server_address().and_then(|address| addrs.iter().position(|&a| a == address));
        let index = match index {
            Some(index) => index.to_string(),
            None => "none".to_string(),
        };
        lines.push(format!("{label} state {state} address {index}"));
    }
    lines
}

/// The address-family refusal edge, fed through the C reference and through this
/// port and compared line by line, not by shape. The C oracle
/// (`["connect_family"]`) drives the reference's client connect with an override
/// transport and an explicit time, the IPv6 socket cleared; the port half is
/// [`connect_family_transcript`]. The port must settle on the same server
/// address index as C, or reach `invalid_connect_token`, on each token.
#[test]
#[ignore = "functional"]
fn connect_family_matches_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("connect_family");

    let c_lines = c_transcript_for(&netcode_c_dir, &["connect_family"]);
    let port_lines = connect_family_transcript();

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port connect_family transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port connect_family transcripts first differ at line {index}: \
             C {c_line:?} vs port {port_line:?}"
        );
    }
}

fn client_state_name(state: netcode::ClientState) -> &'static str {
    match state {
        netcode::ClientState::ConnectTokenExpired => "connect_token_expired",
        netcode::ClientState::InvalidConnectToken => "invalid_connect_token",
        netcode::ClientState::ConnectionTimedOut => "connection_timed_out",
        netcode::ClientState::ConnectionResponseTimedOut => "connection_response_timed_out",
        netcode::ClientState::ConnectionRequestTimedOut => "connection_request_timed_out",
        netcode::ClientState::ConnectionDenied => "connection_denied",
        netcode::ClientState::Disconnected => "disconnected",
        netcode::ClientState::SendingConnectionRequest => "sending_connection_request",
        netcode::ClientState::SendingConnectionResponse => "sending_connection_response",
        netcode::ClientState::Connected => "connected",
    }
}

/// Boolean properties of two started servers and of one server stopped and started
/// again, plus the state after a client connects, disconnects and connects with the
/// same token. Random sequence values are not printed.
fn global_nonce_transcript() -> Vec<String> {
    let key = netcode::generate_key();
    let mut server_a = netcode::Server::new("127.0.0.1:0".parse().unwrap(), 1, &key, 0.0).unwrap();
    let mut server_b = netcode::Server::new("127.0.0.1:0".parse().unwrap(), 1, &key, 0.0).unwrap();
    server_a.start(1).unwrap();
    server_b.start(1).unwrap();

    let floor = 1u64 << 63;
    let mut lines = vec![
        format!("start-a above-floor {}", u8::from(server_a.global_sequence() >= floor)),
        format!("start-b above-floor {}", u8::from(server_b.global_sequence() >= floor)),
        format!(
            "pair differ {}",
            u8::from(server_a.global_sequence() != server_b.global_sequence())
        ),
    ];

    let first = server_a.global_sequence();
    server_a.stop();
    server_a.start(1).unwrap();
    lines.push(format!("restart above-floor {}", u8::from(server_a.global_sequence() >= floor)));
    lines.push(format!("restart differ {}", u8::from(server_a.global_sequence() != first)));

    let address = "127.0.0.1:40000".parse().unwrap();
    let token = netcode::generate_connect_token(
        &[address],
        &[address],
        30,
        10,
        1,
        0x1122334455667788,
        &key,
        &[0u8; netcode::USER_DATA_BYTES],
    )
    .unwrap();
    let mut client = netcode::Client::new("127.0.0.1:0".parse().unwrap(), 0.0).unwrap();
    let _ = client.connect(&token);
    client.disconnect();
    let _ = client.connect(&token);
    lines.push(format!("client reuse {}", client_state_name(client.state())));
    lines
}

/// Two servers started from fresh, and one server stopped and started again, plus a
/// client that connects, disconnects and connects with the same token. The C oracle
/// (built with `-DNETCODE_ORACLE_GLOBAL_NONCE`) drives the reference with an override
/// transport and an explicit time. Each sequence line is `<step> <property> <0|1>`;
/// the client line is `client reuse <state>`. Random values are not printed.
///
/// Written against mas-bandwidth/netcode branch `sprint/netcode-audit-fixes` at
/// or after `1c58478` (the land of
/// `netfix-global-packet-nonces-differ-between-servers-sharing-a-token`).
#[test]
#[ignore = "functional"]
fn global_nonces_match_the_c_reference() {
    let netcode_c_dir = require_netcode_c_dir("global_nonce");

    let c_lines = c_transcript_cc(&netcode_c_dir, &[], &["-DNETCODE_ORACLE_GLOBAL_NONCE"]);
    let port_lines = global_nonce_transcript();
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        eprintln!("compare {index}: C {c_line:?} port {port_line:?}");
    }

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port global_nonce transcripts have different lengths: C {} vs port {}",
        c_lines.len(),
        port_lines.len()
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        if c_line != port_line {
            eprintln!("first differing line {index}: C {c_line:?} vs port {port_line:?}");
        }
        assert_eq!(
            c_line, port_line,
            "C and port global_nonce transcripts first differ at line {index}: \
             C {c_line:?} vs port {port_line:?}"
        );
    }
}
