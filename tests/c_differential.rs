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
//! `#[ignore]`d and gated on `NETCODE_C_DIR` so the unit gate stays hermetic:
//!
//! ```console
//! NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1
//! ```
//!
//! `NETCODE_C_DIR` must be a checkout of mas-bandwidth/netcode holding the fix
//! (branch `sprint/netcode-audit-fixes` at or after `7cd5f513`).

use std::path::PathBuf;
use std::process::Command;

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
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/c/oracle.c");
    let out_dir = std::env::temp_dir().join("netcode-c-differential");
    std::fs::create_dir_all(&out_dir).expect("create temp build dir");
    let binary = out_dir.join("oracle");

    let status = Command::new("cc")
        .args(["-O2", "-ffp-contract=off", "-finstrument-functions"])
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
#[ignore = "requires a C reference checkout; see the file docs"]
fn receive_drain_matches_the_c_reference() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential: NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix, then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

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
#[ignore = "requires a C reference checkout; see the file docs"]
fn challenge_token_binds_matches_the_c_reference() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential: NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix (branch sprint/netcode-audit-fixes at or after \
             5cc4798d), then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

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
#[ignore = "requires a C reference checkout; see the file docs"]
fn disconnect_paths_match_the_c_reference() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential (disconnect): NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix, then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

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
#[ignore = "requires a C reference checkout; see the file docs"]
fn replay_edges_match_the_c_reference() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential (replay): NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix (branch sprint/netcode-audit-fixes at or after \
             406e8d28), then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

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
#[ignore = "requires a C reference checkout; see the file docs"]
fn token_lifetimes_match_the_c_reference() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential (lifetime): NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix (branch sprint/netcode-audit-fixes at or after \
             the commit that lands netfix-never-expiring-tokens-are-refused-or-documented-against-the-restart-floor), \
             then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

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
#[ignore = "requires a C reference checkout; see the file docs"]
fn connect_family_matches_the_c_reference() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential (connect_family): NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix (branch sprint/netcode-audit-fixes at or after \
             the commit that lands netfix-client-refuses-a-server-address-it-has-no-socket-for), \
             then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

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
