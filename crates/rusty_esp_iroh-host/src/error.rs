//! One error for the host side.

use rusty_esp_iroh_core::esp_core::error::Error;
use rusty_esp_iroh_core::rpc::RpcError;

/// What can go wrong dialing or serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The endpoint could not bind.
    Bind(String),
    /// The connection could not be made.
    Connect(String),
    /// A stream failed mid-way.
    Stream(String),
    /// The other side did not answer in time.
    Timeout,
    /// A Janus protocol error (framing, format, crypto).
    Protocol(Error),
    /// The device refused or failed the request.
    Rpc(RpcError),
    /// Sidecar JSON did not parse.
    Json(String),
}

impl core::fmt::Display for HostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HostError::Bind(s) => write!(f, "bind: {s}"),
            HostError::Connect(s) => write!(f, "connect: {s}"),
            HostError::Stream(s) => write!(f, "stream: {s}"),
            HostError::Timeout => f.write_str("timeout"),
            HostError::Protocol(e) => write!(f, "protocol: {e}"),
            HostError::Rpc(e) => write!(f, "rpc: {e:?}"),
            HostError::Json(s) => write!(f, "json: {s}"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<Error> for HostError {
    fn from(e: Error) -> Self {
        HostError::Protocol(e)
    }
}

/// Shorthand.
pub type Result<T> = core::result::Result<T, HostError>;
