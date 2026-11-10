//! Non-blocking UDP sockets with large kernel buffers, plus an in-memory transport for
//! deterministic unit tests.

#[cfg(test)]
use std::collections::{HashMap, VecDeque};
use std::io;
#[cfg(test)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::{SocketAddr, SocketAddrV6, UdpSocket};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use log::{error, info};
use socket2::{Domain, Protocol, Socket, Type};

const SOCKET_SNDBUF_SIZE: usize = 4 * 1024 * 1024;
const SOCKET_RCVBUF_SIZE: usize = 4 * 1024 * 1024;

/// Smallest buffer size requested. Matches the reference implementation.
const SOCKET_BUFFER_MIN_SIZE: usize = 64 * 1024;

/// Set a socket buffer size, halving until the OS accepts it.
///
/// Linux and Windows CLAMP a request above the OS limit and return success. The BSDs
/// REJECT it instead (a stock NetBSD rejects anything over about 227 KiB), so a straight
/// `set_send_buffer_size(4MB)?` fails outright and nothing can start at all.
///
/// Semantics ported from the reference implementation: try sizes from the requested one
/// down to the minimum, halving each time. A larger buffer is an optimisation, never a
/// requirement: if no size is accepted the socket keeps the OS default. Returns the size
/// accepted, or `None` if the OS default was kept.
fn set_buffer_with_backoff(
    requested: usize,
    label: &str,
    mut set: impl FnMut(usize) -> io::Result<()>,
) -> Option<usize> {
    let mut size = requested;
    while size >= SOCKET_BUFFER_MIN_SIZE {
        if set(size).is_ok() {
            if size != requested {
                info!("socket {label} buffer size reduced from {requested} to {size}");
            }
            return Some(size);
        }
        size /= 2;
    }
    info!("socket {label} buffer size kept at the OS default ({requested} was not accepted)");
    None
}

pub(crate) enum Transport {
    Udp(UdpSocket),
    #[cfg(test)]
    Memory(MemorySocket),
}

impl Transport {
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(socket) => socket.local_addr(),
            #[cfg(test)]
            Self::Memory(socket) => Ok(socket.local_addr()),
        }
    }

    pub(crate) fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send_to(buf, target),
            #[cfg(test)]
            Self::Memory(socket) => Ok(socket.send_to(buf, target)),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MemoryNetwork {
    inner: Arc<Mutex<MemoryNetworkInner>>,
}

#[cfg(test)]
struct MemoryNetworkInner {
    next_port: u16,
    queues: HashMap<SocketAddr, VecDeque<(Vec<u8>, SocketAddr)>>,
}

#[cfg(test)]
const FIRST_DYNAMIC_PORT: u16 = 49152;

#[cfg(test)]
impl Default for MemoryNetworkInner {
    fn default() -> Self {
        Self { next_port: FIRST_DYNAMIC_PORT, queues: HashMap::new() }
    }
}

#[cfg(test)]
impl MemoryNetwork {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn bind(&self, address: SocketAddr) -> MemorySocket {
        let mut inner = self.inner.lock().unwrap();
        let ip = match address.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            other => other,
        };
        let port = if address.port() == 0 {
            let start = inner.next_port;
            loop {
                let port = inner.next_port;
                inner.next_port = if port == u16::MAX {
                    FIRST_DYNAMIC_PORT
                } else {
                    (port + 1).max(FIRST_DYNAMIC_PORT)
                };
                let candidate = normalize_address(SocketAddr::new(ip, port));
                if !inner.queues.contains_key(&candidate) {
                    break port;
                }
                assert_ne!(inner.next_port, start, "no free in-memory ports remain");
            }
        } else {
            address.port()
        };
        let bound = normalize_address(SocketAddr::new(ip, port));
        inner.queues.entry(bound).or_default();
        MemorySocket { address: bound, network: Arc::clone(&self.inner) }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct MemorySocket {
    address: SocketAddr,
    network: Arc<Mutex<MemoryNetworkInner>>,
}

#[cfg(test)]
impl MemorySocket {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn send_to(&self, buf: &[u8], target: SocketAddr) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let target = normalize_address(target);
        let mut inner = self.network.lock().unwrap();
        if let Some(queue) = inner.queues.get_mut(&target) {
            queue.push_back((buf.to_vec(), self.address));
        }
        buf.len()
    }

    pub(crate) fn recv_from(&self, buffer: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let mut inner = self.network.lock().unwrap();
        let queue = inner.queues.get_mut(&self.address)?;
        let (data, from) = queue.pop_front()?;
        let len = data.len().min(buffer.len());
        buffer[..len].copy_from_slice(&data[..len]);
        Some((len, from))
    }
}

pub(crate) fn create_socket(address: SocketAddr) -> io::Result<Transport> {
    let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| socket.set_send_buffer_size(size));
    set_buffer_with_backoff(SOCKET_RCVBUF_SIZE, "receive", |size| {
        socket.set_recv_buffer_size(size)
    });
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(Transport::Udp(socket.into()))
}

/// Consecutive receive errors skipped before giving up for this call. Bounds the
/// work done when the socket reports an error that does not clear on its own.
const MAX_RECEIVE_ERRORS: usize = 16;

/// Receives one packet if available. Returns `None` when the socket would block.
pub(crate) fn receive_packet(socket: &Transport, buffer: &mut [u8]) -> Option<(usize, SocketAddr)> {
    match socket {
        Transport::Udp(socket) => receive_packet_with(buffer, |buffer| socket.recv_from(buffer)),
        #[cfg(test)]
        Transport::Memory(socket) => {
            receive_packet_with(buffer, |buffer| match socket.recv_from(buffer) {
                Some((packet_bytes, from)) => Ok((packet_bytes, from)),
                None => Err(io::ErrorKind::WouldBlock.into()),
            })
        }
    }
}

/// Receive loop, parameterised over the actual receive call so the queue
/// handling can be exercised without a live socket. Empty datagrams are legal
/// and are skipped; only a would-block ends the receive queue for this call.
pub(crate) fn receive_packet_with(
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
pub(crate) fn normalize_address(address: SocketAddr) -> SocketAddr {
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
        io::Error::from_raw_os_error(55)
    }

    /// When the OS accepts the full 4 MB on the first call, no halving happens and only
    /// one attempt is made.
    #[test]
    fn accepts_the_requested_size_when_the_os_allows_it() {
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            Ok(())
        });
        assert_eq!(got, Some(SOCKET_SNDBUF_SIZE));
        assert_eq!(*attempts.borrow(), vec![SOCKET_SNDBUF_SIZE]);
    }

    /// BSD behaviour: the kernel rejects requests above its cap with ENOBUFS rather than
    /// clamping them, which is what the backoff loop exists FOR. OpenBSD's default sb_max
    /// is well under 4 MB, so the large requests are rejected and the socket must settle
    /// for what fits rather than refusing to start.
    #[test]
    fn backs_off_by_halving_until_the_os_accepts() {
        let limit = 1024 * 1024;
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            if size > limit { Err(enobufs()) } else { Ok(()) }
        });
        assert_eq!(got, Some(limit));
        // 4M rejected, 2M rejected, 1M accepted -- halving, not jumping to the floor
        assert_eq!(*attempts.borrow(), vec![4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024]);
    }

    /// A stock NetBSD accepts about 227 KiB: 4M, 2M, 1M, 512K and 256K are refused and
    /// 128K is taken.
    #[test]
    fn backs_off_below_256k_when_the_os_limit_is_lower() {
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            if size > 227 * 1024 { Err(enobufs()) } else { Ok(()) }
        });
        assert_eq!(got, Some(128 * 1024));
        assert_eq!(attempts.borrow().len(), 6);
    }

    /// An OS that refuses every size down to the minimum keeps its default buffer: not an
    /// error, and no size below the minimum is ever requested.
    #[test]
    fn keeps_the_os_default_when_no_size_is_accepted() {
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| {
            attempts.borrow_mut().push(size);
            Err(enobufs())
        });
        assert_eq!(got, None);

        let attempts = attempts.borrow();
        assert!(
            attempts.iter().all(|&size| size >= SOCKET_BUFFER_MIN_SIZE),
            "attempted a size below the minimum: {attempts:?}"
        );
        assert_eq!(*attempts.last().unwrap(), SOCKET_BUFFER_MIN_SIZE);
        assert_eq!(attempts.len(), 7);
    }

    /// A request already below the minimum is not made at all.
    #[test]
    fn does_not_request_a_size_below_the_minimum() {
        let attempts = RefCell::new(Vec::new());
        let got = set_buffer_with_backoff(32 * 1024, "send", |size| {
            attempts.borrow_mut().push(size);
            Ok(())
        });
        assert_eq!(got, None);
        assert!(attempts.borrow().is_empty());
    }

    #[test]
    fn memory_network_routes_packets_and_assigns_ephemeral_ports() {
        let network = MemoryNetwork::new();
        let a = Transport::Memory(network.bind("127.0.0.1:0".parse().unwrap()));
        let b = Transport::Memory(network.bind("[::1]:0".parse().unwrap()));
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        assert_ne!(a_addr.port(), 0);
        assert_ne!(b_addr.port(), 0);

        let mut buf = [0u8; 64];
        assert!(receive_packet(&a, &mut buf).is_none());

        a.send_to(&[1, 2, 3, 4], b_addr).unwrap();
        let (len, from) = receive_packet(&b, &mut buf).unwrap();
        assert_eq!(&buf[..len], &[1, 2, 3, 4]);
        assert_eq!(from, a_addr);
        assert!(receive_packet(&b, &mut buf).is_none());
    }

    #[test]
    fn memory_network_skips_ports_already_bound() {
        let network = MemoryNetwork::new();
        // Bind the first port the allocator would otherwise hand out, then ask for an
        // ephemeral one: it must not alias the fixed socket's address and queue.
        let fixed = Transport::Memory(network.bind("127.0.0.1:49152".parse().unwrap()));
        let dynamic = Transport::Memory(network.bind("127.0.0.1:0".parse().unwrap()));
        let fixed_addr = fixed.local_addr().unwrap();
        let dynamic_addr = dynamic.local_addr().unwrap();
        assert_ne!(dynamic_addr, fixed_addr);

        let mut buf = [0u8; 64];
        dynamic.send_to(b"to fixed", fixed_addr).unwrap();
        let (len, from) = receive_packet(&fixed, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"to fixed");
        assert_eq!(from, dynamic_addr);
        // the dynamic socket's own queue stayed separate
        assert!(receive_packet(&dynamic, &mut buf).is_none());
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
