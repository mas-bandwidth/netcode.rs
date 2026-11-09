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
impl Default for MemoryNetworkInner {
    fn default() -> Self {
        Self { next_port: 49152, queues: HashMap::new() }
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
            let port = inner.next_port;
            inner.next_port = inner.next_port.wrapping_add(1).max(49152);
            port
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
        if data.is_empty() {
            return None;
        }
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
    set_buffer_with_backoff(SOCKET_SNDBUF_SIZE, "send", |size| socket.set_send_buffer_size(size))?;
    set_buffer_with_backoff(SOCKET_RCVBUF_SIZE, "receive", |size| {
        socket.set_recv_buffer_size(size)
    })?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(Transport::Udp(socket.into()))
}

/// Receives one packet if available. Returns `None` when the socket would block.
pub(crate) fn receive_packet(socket: &Transport, buffer: &mut [u8]) -> Option<(usize, SocketAddr)> {
    match socket {
        Transport::Udp(socket) => loop {
            match socket.recv_from(buffer) {
                Ok((0, _)) => return None,
                Ok((packet_bytes, from)) => return Some((packet_bytes, normalize_address(from))),
                Err(error) => match error.kind() {
                    io::ErrorKind::WouldBlock => return None,
                    // ICMP port unreachable surfaces as a connection error on some
                    // platforms; skip it and keep reading
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => continue,
                    _ => {
                        error!("recvfrom failed: {error}");
                        return None;
                    }
                },
            }
        },
        #[cfg(test)]
        Transport::Memory(socket) => socket
            .recv_from(buffer)
            .map(|(packet_bytes, from)| (packet_bytes, normalize_address(from))),
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
        })
        .unwrap();
        assert_eq!(got, SOCKET_SNDBUF_SIZE);
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
}
