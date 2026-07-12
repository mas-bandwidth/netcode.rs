//! Little-endian wire format reading and writing.
//!
//! All netcode data is written in little-endian byte order, including sequence numbers
//! converted to nonce values and associated data passed to the AEAD primitives.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub(crate) const ADDRESS_IPV4: u8 = 1;
pub(crate) const ADDRESS_IPV6: u8 = 2;

/// Writes little-endian values into a fixed-size buffer.
///
/// Writes past the end of the buffer panic: every buffer written by this crate has a
/// size fixed by the standard, so an overflow is a bug, not a runtime condition.
pub(crate) struct Writer<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buffer[self.position] = value;
        self.position += 1;
    }

    pub fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer[self.position..self.position + bytes.len()].copy_from_slice(bytes);
        self.position += bytes.len();
    }

    /// Zero the rest of the buffer. Variable-size data is written into fixed-size
    /// buffers and the unused bytes must be zero padded.
    pub fn zero_pad_to_end(&mut self) {
        self.buffer[self.position..].fill(0);
        self.position = self.buffer.len();
    }

    pub fn write_address(&mut self, address: SocketAddr) {
        match address {
            SocketAddr::V4(address) => {
                self.write_u8(ADDRESS_IPV4);
                self.write_bytes(&address.ip().octets());
                self.write_u16(address.port());
            }
            SocketAddr::V6(address) => {
                self.write_u8(ADDRESS_IPV6);
                for segment in address.ip().segments() {
                    self.write_u16(segment);
                }
                self.write_u16(address.port());
            }
        }
    }
}

/// Reads little-endian values from a buffer, returning `None` past the end or on
/// malformed data. Network input is untrusted, so every read is checked.
pub(crate) struct Reader<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, position: 0 }
    }

    fn read_slice(&mut self, length: usize) -> Option<&'a [u8]> {
        let slice = self.buffer.get(self.position..self.position + length)?;
        self.position += length;
        Some(slice)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        let byte = *self.buffer.get(self.position)?;
        self.position += 1;
        Some(byte)
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.read_slice(2)?.try_into().unwrap()))
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.read_slice(4)?.try_into().unwrap()))
    }

    pub fn read_u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.read_slice(8)?.try_into().unwrap()))
    }

    pub fn read_bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        Some(self.read_slice(N)?.try_into().unwrap())
    }

    pub fn read_address(&mut self) -> Option<SocketAddr> {
        match self.read_u8()? {
            ADDRESS_IPV4 => {
                let octets: [u8; 4] = self.read_bytes()?;
                let port = self.read_u16()?;
                Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port)))
            }
            ADDRESS_IPV6 => {
                let mut segments = [0u16; 8];
                for segment in &mut segments {
                    *segment = self.read_u16()?;
                }
                let port = self.read_u16()?;
                Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(segments), port, 0, 0)))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut buffer = [0u8; 64];
        let mut writer = Writer::new(&mut buffer);
        writer.write_u8(0xAB);
        writer.write_u16(0x1234);
        writer.write_u32(0xDEADBEEF);
        writer.write_u64(0x1122334455667788);
        writer.write_bytes(&[1, 2, 3]);
        let written = writer.position();

        let mut reader = Reader::new(&buffer[..written]);
        assert_eq!(reader.read_u8(), Some(0xAB));
        assert_eq!(reader.read_u16(), Some(0x1234));
        assert_eq!(reader.read_u32(), Some(0xDEADBEEF));
        assert_eq!(reader.read_u64(), Some(0x1122334455667788));
        assert_eq!(reader.read_bytes::<3>(), Some([1, 2, 3]));
        assert_eq!(reader.read_u8(), None);
    }

    #[test]
    fn little_endian_on_the_wire() {
        let mut buffer = [0u8; 8];
        Writer::new(&mut buffer).write_u64(0x1122334455667788);
        assert_eq!(buffer, [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn address_round_trip() {
        let addresses: [SocketAddr; 3] = [
            "127.0.0.1:40000".parse().unwrap(),
            "[::1]:50000".parse().unwrap(),
            "[fe80::202:b3ff:fe1e:8329]:65535".parse().unwrap(),
        ];
        for address in addresses {
            let mut buffer = [0u8; 32];
            let mut writer = Writer::new(&mut buffer);
            writer.write_address(address);
            let written = writer.position();
            let mut reader = Reader::new(&buffer[..written]);
            assert_eq!(reader.read_address(), Some(address));
        }
    }

    #[test]
    fn invalid_address_type_rejected() {
        let buffer = [3u8, 0, 0, 0, 0, 0, 0];
        assert_eq!(Reader::new(&buffer).read_address(), None);
    }
}
