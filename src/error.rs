use std::fmt;
use std::io;

use crate::{MAX_CLIENTS, MAX_PAYLOAD_BYTES, MAX_SERVERS_PER_CONNECT};

/// Errors returned by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A connect token failed to parse or contained an invalid field.
    InvalidConnectToken,
    /// AEAD encryption failed.
    EncryptFailed,
    /// AEAD decryption failed. The data was tampered with or the wrong key was used.
    DecryptFailed,
    /// A payload size was outside the range `[1, MAX_PAYLOAD_BYTES]`.
    InvalidPayloadSize(usize),
    /// The number of server addresses was outside the range `[1, MAX_SERVERS_PER_CONNECT]`,
    /// or the public and internal address lists had different lengths.
    InvalidServerAddresses,
    /// The requested number of client slots was outside the range `[1, MAX_CLIENTS]`.
    InvalidMaxClients(usize),
    /// A socket operation failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConnectToken => write!(f, "invalid connect token"),
            Error::EncryptFailed => write!(f, "encryption failed"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::InvalidPayloadSize(size) => {
                write!(f, "payload size {size} is out of range [1,{MAX_PAYLOAD_BYTES}]")
            }
            Error::InvalidServerAddresses => write!(
                f,
                "number of server addresses is out of range [1,{MAX_SERVERS_PER_CONNECT}] \
                 or public and internal address lists differ in length"
            ),
            Error::InvalidMaxClients(n) => {
                write!(f, "max clients {n} is out of range [1,{MAX_CLIENTS}]")
            }
            Error::Io(error) => write!(f, "socket error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}
