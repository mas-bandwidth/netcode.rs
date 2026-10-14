//! Non-blocking UDP sockets with large kernel buffers.

use std::io;
use std::net::{SocketAddr, SocketAddrV6, UdpSocket};

use log::{error, info};
use socket2::{Domain, Protocol, Socket, Type};

const SOCKET_SNDBUF_SIZE: usize = 4 * 1024 * 1024;
const SOCKET_RCVBUF_SIZE: usize = 4 * 1024 * 1024;

/// Smallest buffer worth having. Below this the socket is not useful for netcode's
/// traffic, so failing is better than pretending. Matches the reference implementation.
const SOCKET_BUFFER_MIN_SIZE: usize = 256 * 1024;

/// Set a socket buffer size, halving until the OS accepts it.
///
/// Linux and Windows CLAMP a request above the OS limit and return success. The BSDs
/// REJECT it with ENOBUFS instead. OpenBSD's default `sb_max` is well under the 4 MB
/// asked for here, so a straight `set_send_buffer_size(4MB)?` fails outright and nothing
/// can start at all -- which is the entire reason the C implementation grew this backoff
/// (netcode 71469837, shipped in v1.3.5).
///
/// Semantics ported exactly: try the requested size, halve on failure, and give up only
/// once the halved size would fall below the floor. So the smallest size ever attempted
/// is at least the floor, and the error surfaced is the one from the last real attempt.
fn set_buffer_with_backoff(
    requested: usize,
    label: &str,
    mut set: impl FnMut(usize) -> io::Result<()>,
) -> io::Result<usize> {
    let mut size = requested;
    loop {
        match set(size) {
            Ok(()) => break,
            Err(error) => {
                size /= 2;
                if size < SOCKET_BUFFER_MIN_SIZE {
                    error!("failed to set socket {label} buffer size");
                    return Err(error);
                }
            }
        }
    }
    if size != requested {
        info!("socket {label} buffer size reduced from {requested} to {size}");
    }
    Ok(size)
}

pub(crate) fn create_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| socket.set_send_buffer_size(size))?;
    set_buffer_with_backoff(SOCKET_RCVBUF_SIZE, "receive", |size| {
        socket.set_recv_buffer_size(size)
    })?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

/// The outcome of one non-blocking receive attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiveStatus {
    /// A datagram of this many bytes arrived.
    Datagram(usize),
    /// This datagram is to be ignored: a zero-length datagram, or a receive
    /// error that is not a would-block. Keep draining.
    Skip,
    /// The socket has no more datagrams this update.
    Drained,
}

/// Classifies one non-blocking receive result into the three-way outcome the
/// receive loops act on.
///
/// A zero-length datagram is legal and `recv_from` reports it as `Ok(0)`;
/// reading that as "the socket is drained" ends the loop for the update and
/// lets an unauthenticated sender of empty datagrams starve every real client.
/// A would-block is the only true drain; any other error skips the datagram
/// and keeps draining. Matches the C reference's classifier rows exactly:
/// `(0, no error)` skips, `(-1, would-block)` drains, `(-1, other error)`
/// skips, and a positive count is a datagram.
pub(crate) fn classify_receive(result: isize, error_kind: Option<io::ErrorKind>) -> ReceiveStatus {
    if result > 0 {
        ReceiveStatus::Datagram(result as usize)
    } else if result == 0 {
        ReceiveStatus::Skip
    } else if error_kind == Some(io::ErrorKind::WouldBlock) {
        ReceiveStatus::Drained
    } else {
        ReceiveStatus::Skip
    }
}

/// Counts from one capped drain: every receive attempt is consumed, every
/// datagram handed on is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DrainCounts {
    pub consumed: usize,
    pub processed: usize,
}

/// Runs one update's receive drain: call `receive` up to `cap` times, skip
/// skipped datagrams, and stop on a drain.
///
/// Every attempt counts toward the cap, so an unauthenticated sender of empty
/// datagrams cannot hold the update open. The server and client use the caps
/// the reference names.
pub(crate) fn drain_with_cap(
    cap: usize,
    mut receive: impl FnMut() -> ReceiveStatus,
) -> DrainCounts {
    let mut counts = DrainCounts::default();
    while counts.consumed < cap {
        counts.consumed += 1;
        match receive() {
            ReceiveStatus::Datagram(_) => counts.processed += 1,
            ReceiveStatus::Skip => {}
            ReceiveStatus::Drained => break,
        }
    }
    counts
}

/// Receives one datagram if available, classifying the result. The source
/// address is present only for a `Datagram`.
pub(crate) fn receive_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> (ReceiveStatus, Option<SocketAddr>) {
    match socket.recv_from(buffer) {
        Ok((packet_bytes, from)) => {
            let status = classify_receive(packet_bytes as isize, None);
            let from = if packet_bytes > 0 { Some(normalize_address(from)) } else { None };
            (status, from)
        }
        Err(error) => (classify_receive(-1, Some(error.kind())), None),
    }
}

/// Test seam for the C differential test: builds the port-side transcript for
/// the scripted receive queues `tests/c/oracle.c` runs. Hidden from docs; not
/// part of the supported API.
#[doc(hidden)]
pub fn differential_transcript() -> Vec<String> {
    let mut lines = Vec::new();

    for (name, status) in [
        ("classifier-0-0", classify_receive(0, None)),
        ("classifier-1-would-block", classify_receive(-1, Some(io::ErrorKind::WouldBlock))),
        ("classifier-1-other", classify_receive(-1, Some(io::ErrorKind::ConnectionRefused))),
        ("classifier-5-0", classify_receive(5, None)),
    ] {
        let processed = usize::from(matches!(status, ReceiveStatus::Datagram(_)));
        lines.push(format!("{name} classifier consumed 1 processed {processed}"));
    }

    fn datagram() -> ReceiveStatus {
        ReceiveStatus::Datagram(12)
    }

    let server_cap = crate::SERVER_MAX_RECEIVE_PACKETS;
    let client_cap = crate::CLIENT_MAX_RECEIVE_PACKETS;

    let scripts: [(&str, Vec<ReceiveStatus>); 4] = [
        ("junk-empty-junk-junk", vec![datagram(), ReceiveStatus::Skip, datagram(), datagram()]),
        (
            "empty-empty-empty-junk",
            vec![ReceiveStatus::Skip, ReceiveStatus::Skip, ReceiveStatus::Skip, datagram()],
        ),
        ("flood", vec![datagram(); server_cap + 10]),
        ("ends-with-drain", vec![datagram(), ReceiveStatus::Skip, ReceiveStatus::Drained]),
    ];

    for (name, script) in scripts {
        for (side, cap) in [("server", server_cap), ("client", client_cap)] {
            let queue = script.clone();
            let mut index = 0;
            let counts = drain_with_cap(cap, || {
                if index < queue.len() {
                    let status = queue[index];
                    index += 1;
                    status
                } else {
                    ReceiveStatus::Drained
                }
            });
            lines.push(format!(
                "{name} {side} consumed {} processed {}",
                counts.consumed, counts.processed
            ));
        }
    }

    lines
}

/// Zeroes the IPv6 flow label and scope id so received addresses compare equal to
/// parsed ones. The reference implementation cannot represent either field, so
/// carrying them here would make otherwise-identical addresses compare unequal and
/// silently drop packets (e.g. from link-local sources, where the OS sets a scope id).
fn normalize_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, 0)),
        SocketAddr::V4(_) => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn enobufs() -> io::Error {
        io::Error::from_raw_os_error(55) // ENOBUFS on the BSDs
    }

    /// The platform this ports FROM: Linux and Windows clamp silently, so the first
    /// attempt succeeds and nothing is reduced.
    #[test]
    fn accepts_the_requested_size_when_the_os_allows_it() {
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            Ok(())
        })
        .unwrap();
        assert_eq!(got, SOCKET_SNDBUF_SIZE);
        assert_eq!(*attempts.borrow(), vec![SOCKET_SNDBUF_SIZE]);
    }

    /// The platform this ports FOR. OpenBSD's default sb_max is well under 4 MB, so the
    /// large requests are rejected and the socket must settle for what fits rather than
    /// refusing to start.
    #[test]
    fn backs_off_by_halving_until_the_os_accepts() {
        let limit = 1024 * 1024;
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            if size > limit { Err(enobufs()) } else { Ok(()) }
        })
        .unwrap();
        assert_eq!(got, limit);
        // 4M rejected, 2M rejected, 1M accepted -- halving, not jumping to the floor
        assert_eq!(*attempts.borrow(), vec![4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024]);
    }

    /// Below the floor the socket is not useful for netcode's traffic, so failing is
    /// better than pretending. The error surfaced is the one from the last real attempt.
    #[test]
    fn gives_up_below_the_floor_rather_than_shrinking_forever() {
        let attempts = RefCell::new(Vec::new());
        let result = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            Err(enobufs())
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().raw_os_error(), Some(55));

        // THE INVARIANT WORTH PINNING: never attempt a size below the floor. A loop that
        // halves before checking would try 128K, 64K, ... and eventually succeed with a
        // uselessly small buffer on a machine that merely has a low limit.
        let attempts = attempts.borrow();
        assert!(
            attempts.iter().all(|&size| size >= SOCKET_BUFFER_MIN_SIZE),
            "attempted a size below the floor: {attempts:?}"
        );
        assert_eq!(*attempts.last().unwrap(), SOCKET_BUFFER_MIN_SIZE);
    }

    /// The classifier's rows, exactly as the C reference fixes them: a zero-length
    /// datagram (`Ok(0)`) is a skip, a would-block is the only drain, any other
    /// receive error is a skip, and a positive count is a datagram.
    #[test]
    fn classify_receive_matches_c_rows() {
        assert_eq!(classify_receive(0, None), ReceiveStatus::Skip);
        assert_eq!(classify_receive(-1, Some(io::ErrorKind::WouldBlock)), ReceiveStatus::Drained);
        assert_eq!(
            classify_receive(-1, Some(io::ErrorKind::ConnectionRefused)),
            ReceiveStatus::Skip
        );
        assert_eq!(classify_receive(5, None), ReceiveStatus::Datagram(5));
    }

    /// The per-update drain: empty datagrams and receive errors are skipped, a
    /// would-block ends it, and a flood is cut off at the cap so an unauthenticated
    /// sender of empty datagrams cannot hold the update open.
    #[test]
    fn drain_with_cap_skips_empty_and_stops_at_the_cap() {
        use std::collections::VecDeque;

        let cap = crate::SERVER_MAX_RECEIVE_PACKETS;

        // A flood of one more than the cap plus ten is consumed exactly to the cap,
        // leaving the rest for the next update.
        let flood = RefCell::new(VecDeque::from(vec![ReceiveStatus::Datagram(1); cap + 10]));
        let counts = drain_with_cap(cap, || {
            flood.borrow_mut().pop_front().unwrap_or(ReceiveStatus::Drained)
        });
        assert_eq!(counts.consumed, cap);
        assert_eq!(counts.processed, cap);
        assert_eq!(flood.borrow().len(), 10);

        // [junk, empty, junk] is drained whole: the empty datagram is skipped and
        // never ends the loop early.
        let queue = RefCell::new(VecDeque::from(vec![
            ReceiveStatus::Datagram(3),
            ReceiveStatus::Skip,
            ReceiveStatus::Datagram(7),
        ]));
        let counts = drain_with_cap(cap, || {
            queue.borrow_mut().pop_front().unwrap_or(ReceiveStatus::Drained)
        });
        assert_eq!(counts.processed, 2);
        assert!(queue.borrow().is_empty());
        // the final would-block attempt is an iteration too, so it counts as consumed
        assert_eq!(counts.consumed, 4);
    }
}
