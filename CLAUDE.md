<!-- HOT:BEGIN -->
WHAT: from-scratch Rust port of netcode 1.02, wire-compatible with the C reference.
NOT mas-bandwidth/netcode (that C reference), NOT netcode.go (the Go port).

NAME TRAP: the crates.io package is `netcode-official`; `netcode` (vvanders) and
`netcode-rs` (benny-n) are held by unrelated projects. The library target is
deliberately still `netcode`, so code says `use netcode::...` and only the Cargo.toml
line changes if that name ever frees up. Do not "fix" the mismatch.

DECISIONS (look like bugs, are not)
- server.rs seeds `global_sequence = 1 << 63` in `new`, `start` AND `stop`. Not
  redundant: seeding on create only is the AEAD nonce-reuse bug found here while
  porting and fixed upstream in C netcode 1.4.0 (IMPLEMENTERS.md #3). Keep all three.
- `ReplayProtection::already_received` uses the subtraction-side test (IMPLEMENTERS.md
  #1); the addition form overflows near u64::MAX. Never restore it.
- Received IPv6 addresses zero the scope id as well as the flow label. The C
  implementation represents neither; keeping them silently drops link-local packets.
- STANDARD.md is a VERBATIM vendored copy of the upstream spec, not a local document.
  Change it upstream first, then copy it across in the same commit as the code change.

INVARIANT: byte-identical wire format with the C reference. src/wire_compat.rs checks
the golden tests/vectors/*.bin on every `cargo test`; the `interop` CI job builds the C
client/server and runs tests/c_interop.rs live.

TRAPS
- `cargo test` alone does NOT run the interop tests: they are `#[ignore]` and need
  NETCODE_C_SERVER / NETCODE_C_CLIENT.
- `interop` and `spec-sync` track mas-bandwidth/netcode's default branch, so an upstream
  commit can fail the next CI run here with no change in this repo.

NEVER regenerate tests/vectors/*.bin to make a test pass: a golden failure means the
change breaks every other netcode implementation. Only a standard change justifies new
vectors.

CARGO.LOCK IS GITIGNORED HERE ON PURPOSE
`.gitignore` lists `Cargo.lock` and `fuzz/Cargo.lock` deliberately, hand-written beside
the fuzz artifacts. This is a library crate: dependents do not use its lock, and this is
the only one of the three Rust ports with real dependencies (57 packages via
chacha20poly1305). serialize.rs and reliable.rs DO commit a lock, but by omission rather
than decision -- neither .gitignore mentions it, and both locks are near-empty (1 and 2
packages) because those crates have essentially no dependencies. Do not "fix" the
inconsistency by adding a lock here; the considered choice is this one.
Note the lock IS packaged into the published .crate, so if this is ever revisited it is
a version site, not just a dev-convenience question.
<!-- HOT:END -->

## Build and test

```console
cargo build --all-targets
cargo test                                   # unit, wire-compatibility and integration tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps                          # CI builds docs with -D warnings
```

MSRV is 1.87 (`rust-version` in Cargo.toml); CI checks it with `cargo check` on that
toolchain. 1.87 is the lowest version on which the dependency tree resolves without the
open advisory RUSTSEC-2026-0385: the resolver honours `rust-version`, and every fixed
`ctutils` (>= 0.4.4, via chacha20poly1305 -> poly1305 -> universal-hash) needs 1.87.

Interop tests, against the C reference built from mas-bandwidth/netcode with CMake:

```console
NETCODE_C_SERVER=path/to/build/bin/server \
NETCODE_C_CLIENT=path/to/build/bin/client \
cargo test --test c_interop -- --ignored --test-threads=1
```

Fuzzing (`cargo install cargo-fuzz`):

```console
cargo +nightly fuzz run fuzz_read_packet
```

## Layout

- `src/` library: `lib.rs`, `client.rs`, `server.rs`, `packet.rs`, `token.rs`,
  `crypto.rs`, `replay.rs`, `socket.rs`, `bytes.rs`, `error.rs`, `wire_compat.rs`
- `tests/` integration tests plus `tests/vectors/` golden binary vectors
- `examples/` `client.rs`, `server.rs`, `client_server.rs`
- `fuzz/` cargo-fuzz targets
- `STANDARD.md` vendored upstream spec (see HOT block)
