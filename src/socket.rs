//! Non-blocking UDP sockets with large kernel buffers.

use std::io;
use std::net::{SocketAddr, SocketAddrV6, UdpSocket};

use log::error;
use socket2::{Domain, Protocol, Socket, Type};

const SOCKET_SNDBUF_SIZE: usize = 4 * 1024 * 1024;
const SOCKET_RCVBUF_SIZE: usize = 4 * 1024 * 1024;

pub(crate) fn create_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_send_buffer_size(SOCKET_SNDBUF_SIZE)?;
    socket.set_recv_buffer_size(SOCKET_RCVBUF_SIZE)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

/// Receives one packet if available. Returns `None` when the socket would block.
pub(crate) fn receive_packet(socket: &UdpSocket, buffer: &mut [u8]) -> Option<(usize, SocketAddr)> {
    loop {
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
