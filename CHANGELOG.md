# Changelog

## Unreleased

Changes on main since v1.1.3.

### Server

- A connection request is refused when its connect token expires at or before the
  server start time plus the maximum connect token lifetime, as in the reference
  implementation. A token issued in the second the server started is therefore refused:
  issue tokens after that second.
- A connect token history entry is consumed by a completed handshake only while the
  entry still holds that handshake's connect token.
- A pending encryption mapping for a token with a negative timeout expires with the
  connect token's remaining lifetime, bounded by the server's maximum token lifetime.
- The configured public address is compared with connect token addresses in the same
  normalized form, so an IPv6 address with a scope id or flow label is accepted.
- The receive loop skips zero-length datagrams and keeps reading, and a single read
  gives up after 16 receive errors.
- The event queue read by `Server::next_event` holds at most `MAX_CLIENTS * 4` events,
  dropping the oldest first. Drain it every update.
- `Server::stop` keeps the events it queues, including a `ClientDisconnected` event for
  each client it disconnects, and any events still undrained, for `next_event`.

### Client

- A connected client that receives a disconnect packet goes to `Disconnected`; it moves
  to the next server address only while connecting.
- Packets from any address other than the current server address are ignored before
  they are authenticated.
- Both sockets are read on every update, and packets received while not connecting or
  connected are discarded.
- Server addresses whose family has no client socket are skipped; a token with no usable
  address goes straight to `InvalidConnectToken`.
- A connection keep-alive is ignored unless `max_clients` is in `1..=MAX_CLIENTS` and
  `client_index` is below `max_clients`.
- Connection timestamps are taken from the time passed to the first `Client::update`
  after `connect`, and kept at the switch time when moving to the next server.

### Packets and tokens

- Packet sequence `u64::MAX` is refused when reading and writing, and by replay
  protection.
- Key material (connect tokens, encryption mappings, server and client keys) is zeroed
  when it is dropped, reset or expired. Adds the `zeroize` dependency.
- A system clock before 1970 reads as timestamp zero.
- A negative `expire_seconds` in `generate_connect_token` is documented as for
  development and testing only.

### Sockets

- When the operating system refuses every socket buffer size from the requested size
  down to 64 KiB, the socket keeps the OS default buffer instead of failing to be
  created, as in the reference implementation.

### Documentation and examples

- `Client::update` and `Server::update` document that time must not move backwards.
- The README, crate example and examples drain `Server::next_event`, and issue connect
  tokens of at most the server's maximum lifetime after the server's start second.
- The published crate no longer includes development files.
