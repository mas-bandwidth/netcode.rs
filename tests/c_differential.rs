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

    let output = Command::new(&binary).output().expect("failed to run the C oracle");
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
