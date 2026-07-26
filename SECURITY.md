# Security Policy

netcode.rs implements an encrypted, connection-oriented protocol over UDP. It parses
untrusted data straight off the wire — packets, connect tokens, and the challenge exchange
— and it holds the keys, so we take memory-safety and protocol bugs seriously.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues or pull requests.**

Report privately through either channel:

- **GitHub private vulnerability reporting** (preferred): on this repository, go to the
  **Security** tab → **Report a vulnerability**. This opens a private advisory visible only
  to the maintainers.
- **Email**: glenn@mas-bandwidth.com.

Please include enough detail to reproduce: the affected version or commit, a description of
the flaw, and — where possible — a proof-of-concept input or a small patch. A failing
`cargo test` case or a fuzz artifact is ideal.

We will acknowledge your report, keep you updated on our assessment, and coordinate
disclosure timing with you. We prefer coordinated disclosure and will credit reporters who
wish to be named.

## Scope

In scope — bugs in this crate: packet parsing, connect token handling, the challenge
exchange, replay protection, and the cryptographic plumbing around them.

Especially of interest: panics or incorrect acceptance reachable from a received packet or
connect token, and protocol flaws that let a peer bypass authentication, encryption, or
replay protection.

The crate is `#![forbid(unsafe_code)]`, enforced by the compiler, so classic memory
corruption is off the table by construction. That makes *logic* flaws the interesting
class here: a panic is a denial of service, and a wrongly-accepted packet is worse.

The protocol itself is specified in `STANDARD.md`. **A flaw in the *specification* — as
opposed to this implementation of it — is in scope and is more valuable to us**, because it
affects every implementation of netcode rather than one. Report those the same way.

## netcode.rs is NOT affected by the AEAD nonce reuse issue

Stated explicitly, because the rest of the netcode family *is* and silence would invite the
wrong inference.

The C implementation seeded its server global packet sequence only on *create* and not on
*start*, so a server stopped and restarted in the same process could reuse a `(key, nonce)`
pair — [GHSA-3x95-24j9-7448](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-3x95-24j9-7448),
affecting `netcode` ≤ 1.3.5. `yojimbo` ≤ 1.6.3 inherited it by vendoring
([GHSA-hqp3-fj6v-hrpc](https://github.com/mas-bandwidth/yojimbo/security/advisories/GHSA-hqp3-fj6v-hrpc)),
and `netcode.go` v1.0.0–v1.0.2 had the same defect independently
([GHSA-wgmm-f3w5-7c6q](https://github.com/mas-bandwidth/netcode.go/security/advisories/GHSA-wgmm-f3w5-7c6q)).

**netcode.rs never shipped that defect.** Its 1.0.0 release already kept the global and
per-client nonce spaces disjoint. The 1.1.0 release is often mistaken for the fix because
of its timing; it was a licence change with no code change.

The property is locked down by tests rather than left to inspection: one takes the sequence
off the wire — decrypting a real challenge packet under the connect token's key and
asserting the nonce stays in the reserved half — and another checks each entry point
restores the floor on its own. The wire-level test exists because the reseed sites are
individually redundant here, so a purely behavioural test cannot catch a single-site
regression.

## Supported versions

Security fixes land on the latest release. We do not backport to older release lines.
