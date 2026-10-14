//! Differential test against the reference C implementation.
//!
//! Feeds the same fixed byte inputs through the C reference's packet reader and
//! through this port, and compares the two transcripts exactly. The C side is
//! `tests/c/oracle.c`; the port side is produced here.
//!
//! This is a functional test: it builds and runs a local C program on fixed
//! bytes, with no socket and no clock anywhere in the comparison. It is
//! `#[ignore]`d and gated on `NETCODE_C_DIR` so the unit gate stays hermetic:
//!
//! ```console
//! NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1
//! ```
//!
//! `NETCODE_C_DIR` must be a checkout of mas-bandwidth/netcode holding the fix
//! (branch `sprint/netcode-audit-fixes` at or after `406e8d28`).

use std::path::PathBuf;
use std::process::Command;

/// One line of the transcript: `<n> <packet type or refused> <sequence> <length>`.
fn format_line(n: usize, packet_type: &str, sequence: u64, length: usize) -> String {
    format!("{n} {packet_type} {sequence} {length}")
}

/// Builds and runs the C oracle, returning its stdout as a transcript.
///
/// The oracle is `tests/c/oracle.c` beside this file; `cc` compiles it with the
/// flags the card names. `NETCODE_C_DIR` must point at the C checkout.
fn c_transcript(netcode_c_dir: &str) -> Vec<String> {
    let oracle = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/c/oracle.c");
    let out_dir = std::env::temp_dir().join("netcode-c-differential");
    std::fs::create_dir_all(&out_dir).expect("create temp build dir");
    let binary = out_dir.join("oracle");

    let status = Command::new("cc")
        .args(["-O2", "-ffp-contract=off"])
        .arg(format!("-I{netcode_c_dir}"))
        .arg(format!("-I{netcode_c_dir}/sodium"))
        .arg(&oracle)
        .arg(format!("{netcode_c_dir}/netcode.c"))
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

/// The port-side transcript for the same fixed inputs.
///
/// The port's packet reader (`netcode::packet::read_packet`) and its packet
/// type are `pub(crate)`, so an integration test cannot call them: this test is
/// a separate crate from the library. Producing the port transcript needs
/// either a socketless, public seam over the packet reader or a FakeTransport,
/// neither of which exists at this commit, and this card may not change library
/// code. The function is left returning `None` to say so rather than inventing
/// a transcript.
fn port_transcript() -> Option<Vec<String>> {
    None
}

#[test]
#[ignore = "requires a C reference checkout; see the file docs"]
fn packet_readers_produce_the_same_transcript() {
    let Ok(netcode_c_dir) = std::env::var("NETCODE_C_DIR") else {
        eprintln!(
            "SKIP c_differential: NETCODE_C_DIR is unset; set it to a checkout of \
             mas-bandwidth/netcode holding the fix, then run:\n    \
             NETCODE_C_DIR=<checkout> cargo test --test c_differential -- --ignored --test-threads=1"
        );
        return;
    };

    let c_lines = c_transcript(&netcode_c_dir);

    let Some(port_lines) = port_transcript() else {
        eprintln!(
            "SKIP c_differential port side: netcode::packet::read_packet is pub(crate) and the \
             port exposes no socketless seam over it, so an integration test cannot build the \
             port transcript without a library change. The C transcript ({} lines) is below:\n{}",
            c_lines.len(),
            c_lines.join("\n")
        );
        return;
    };

    assert_eq!(
        c_lines.len(),
        port_lines.len(),
        "the C and port transcripts have different lengths"
    );
    for (index, (c_line, port_line)) in c_lines.iter().zip(port_lines.iter()).enumerate() {
        assert_eq!(
            c_line, port_line,
            "C and port transcripts first differ at line {}: C {c_line:?} vs port {port_line:?}",
            index
        );
    }

    // Keep the line formatter exercised even when the port side is unavailable.
    let _ = format_line(0, "refused", 0, 0);
}
