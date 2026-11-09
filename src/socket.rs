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

/// Consecutive receive errors skipped before giving up for this call. Bounds the
/// work done when the socket reports an error that does not clear on its own.
const MAX_RECEIVE_ERRORS: usize = 16;

/// Receives one packet if available. Returns `None` when the socket would block.
pub(crate) fn receive_packet(socket: &UdpSocket, buffer: &mut [u8]) -> Option<(usize, SocketAddr)> {
    receive_packet_with(buffer, |buffer| socket.recv_from(buffer))
}

/// Receive loop, parameterised over the actual receive call so the queue
/// handling can be exercised without a live socket. Empty datagrams are legal
/// and are skipped; only a would-block ends the receive queue for this call.
fn receive_packet_with(
    buffer: &mut [u8],
    mut recv_from: impl FnMut(&mut [u8]) -> io::Result<(usize, SocketAddr)>,
) -> Option<(usize, SocketAddr)> {
    let mut errors = 0;
    loop {
        match recv_from(buffer) {
            Ok((0, _)) => continue,
            Ok((packet_bytes, from)) => return Some((packet_bytes, normalize_address(from))),
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock => return None,
                // ICMP port unreachable surfaces as a connection error on some
                // platforms; skip it and keep reading
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => errors += 1,
                _ => {
                    error!("recvfrom failed: {error}");
                    errors += 1;
                }
            },
        }
        if errors >= MAX_RECEIVE_ERRORS {
            return None;
        }
    }
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

    #[test]
    fn empty_datagrams_are_skipped_not_treated_as_drained() {
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut results = vec![Ok((0, addr)), Ok((0, addr)), Ok((5, addr))].into_iter();
        let mut buffer = [0u8; 64];

        let received = receive_packet_with(&mut buffer, |_| results.next().unwrap());

        assert_eq!(received, Some((5, addr)));
        assert!(results.next().is_none(), "the packet after the empty datagrams was not read");
    }

    #[test]
    fn would_block_is_the_end_of_the_receive_queue() {
        let mut attempts = 0;
        let mut buffer = [0u8; 64];

        let received = receive_packet_with(&mut buffer, |_| {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        });

        assert!(received.is_none());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn receive_errors_are_bounded_per_call() {
        let mut attempts = 0;
        let mut buffer = [0u8; 64];

        let received = receive_packet_with(&mut buffer, |_| {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::Other))
        });

        assert!(received.is_none());
        assert_eq!(attempts, MAX_RECEIVE_ERRORS);
    }
}
