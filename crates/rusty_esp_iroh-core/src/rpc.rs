//! `janus/rpc/1`: one request and one response per bi-stream, each a
//! length-prefixed postcard frame; every request may carry the caller's
//! mID [`Assertion`], and the device's authorisation rule decides what an
//! unauthenticated caller may ask.
//!
//! Compatibility rule, from n0's smart-fan example and irpc practice: new
//! variants are added at the **end** of [`Request`] and [`Response`], never
//! inserted or reordered, so an older node decodes what it knows and answers
//! [`RpcError::Unsupported`] to the rest.

use alloc::string::String;
use alloc::vec::Vec;

use rusty_esp_core::error::{Error, Result};
use rusty_esp_mid_core::adoption::OwnerPin;
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::nonce::NonceWindow;
use serde::{Deserialize, Serialize};

use crate::alpn::MAX_RPC_FRAME;
use crate::assertion::Assertion;

/// A request with its optional caller assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Who is asking, if they say so.
    pub assertion: Option<WireAssertion>,
    /// What they ask.
    pub request: Request,
}

/// The owned wire form of an [`Assertion`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAssertion {
    /// Caller DID.
    pub caller_did: String,
    /// Device DID.
    pub audience_did: String,
    /// Single-use nonce.
    pub nonce: [u8; 32],
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
    /// 64-byte low-s signature.
    pub sig: Vec<u8>,
}

impl WireAssertion {
    /// Wrap a borrowed assertion.
    #[must_use]
    pub fn from_assertion(a: &Assertion<'_>) -> Self {
        WireAssertion {
            caller_did: String::from(a.caller_did),
            audience_did: String::from(a.audience_did),
            nonce: *a.nonce,
            issued_at: a.issued_at,
            expires_at: a.expires_at,
            sig: a.sig.to_vec(),
        }
    }

    /// Borrow as an [`Assertion`] (rejects a signature of the wrong length).
    pub fn as_assertion(&self) -> Result<Assertion<'_>> {
        let sig: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        Ok(Assertion {
            caller_did: &self.caller_did,
            audience_did: &self.audience_did,
            nonce: &self.nonce,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            sig,
        })
    }
}

/// What a caller may ask a device. **Append only.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Liveness.
    Ping,
    /// The signed capability manifest.
    Manifest,
    /// Live counters.
    Telemetry,
    /// Install an owner-signed adoption (the encoded `Adoption` bytes).
    Adopt(Vec<u8>),
    /// Invoke a capability by its manifest tag with opaque arguments.
    Call {
        /// Capability tag, as in the manifest.
        capability: String,
        /// Postcard-encoded arguments, capability-specific.
        args: Vec<u8>,
    },
    /// The device's current rendezvous ticket (text form).
    Ticket,
    /// The device's monotonic clock, for the host's one-shot
    /// [`WallOffset`](rusty_esp_core::time::WallOffset). Public.
    Time,
    /// An update, on `janus/ota/1` only (the image bytes follow the
    /// envelope on the same stream); on `janus/rpc/1` it is `Unsupported`.
    /// Owner.
    Ota(crate::ota::OtaManifest),
    /// The neighbours a bridge fronts (see the `-bridge` crate). Public.
    Neighbours,
}

/// Who may ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone who can reach the endpoint.
    Public,
    /// Only the pinned owner.
    Owner,
}

impl Request {
    /// The access level a request needs.
    #[must_use]
    pub fn access(&self) -> Access {
        match self {
            Request::Ping
            | Request::Manifest
            | Request::Ticket
            | Request::Time
            | Request::Neighbours => Access::Public,
            Request::Telemetry | Request::Adopt(_) | Request::Call { .. } | Request::Ota(_) => {
                Access::Owner
            }
        }
    }
}

/// Live counters a device reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Telemetry {
    /// Microseconds since boot.
    pub uptime_us: u64,
    /// Free heap bytes.
    pub heap_free: u32,
    /// Lowest free heap seen.
    pub heap_min: u32,
    /// Wi-Fi RSSI in dBm, 0 when unknown.
    pub rssi_dbm: i8,
    /// Firmware identifier.
    pub fw: String,
}

/// What a device answers. **Append only.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// To [`Request::Ping`].
    Pong,
    /// To [`Request::Manifest`].
    Manifest {
        /// `rusty_esp_core::capability::Manifest::encode` bytes.
        bytes: Vec<u8>,
        /// `rusty_esp_mid_core::manifest::sign_manifest` signature.
        sig: Vec<u8>,
        /// The device DID the signature verifies under.
        did: String,
    },
    /// To [`Request::Telemetry`].
    Telemetry(Telemetry),
    /// To [`Request::Adopt`]: the roster version now pinned.
    Adopted {
        /// Pinned roster version.
        roster_version: u32,
    },
    /// To [`Request::Call`]: capability-specific result bytes.
    Result(Vec<u8>),
    /// To [`Request::Ticket`].
    Ticket(String),
    /// Any failure.
    Error(RpcError),
    /// Answer to [`Request::Time`]: device monotonic microseconds.
    Time {
        /// The device clock when the request was handled.
        device_us: u64,
    },
    /// The OTA manifest passed every check; the image bytes may follow.
    OtaReady,
    /// The image is in the boot slot.
    OtaResult {
        /// The firmware string the device will report after it boots.
        firmware: String,
        /// The digest the device computed.
        sha256: [u8; 32],
    },
    /// Answer to [`Request::Neighbours`].
    Neighbours(Vec<NeighbourInfo>),
}

/// One device a bridge fronts: its own DID and its own signed manifest,
/// relayed verbatim so the reader verifies the neighbour's signature, not
/// the bridge's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighbourInfo {
    /// The neighbour's `did:mata`.
    pub did: String,
    /// How it reaches the bridge: `espnow`, `lora`, ...
    pub reach: String,
    /// Its manifest, canonical bytes.
    pub manifest: Vec<u8>,
    /// The neighbour's signature over `manifest`.
    pub sig: Vec<u8>,
    /// Bridge-clock microseconds since the last authenticated frame.
    pub last_seen_us: u64,
}

/// Why a request was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcError {
    /// The request needs an assertion and carried none.
    Unauthorized,
    /// The assertion was present but not acceptable (wrong owner, replay, expired, bad signature).
    Denied,
    /// The device does not implement this request or capability.
    Unsupported,
    /// The frame or its contents did not parse.
    Malformed,
    /// Something else, with a short reason.
    Internal(String),
    /// The request was well formed and authorised and the device still
    /// said no, with the reason (an OTA refusal names its check).
    Refused(String),
}

impl From<Error> for RpcError {
    fn from(e: Error) -> Self {
        match e {
            Error::Denied | Error::Crypto => RpcError::Denied,
            Error::Unsupported => RpcError::Unsupported,
            Error::InvalidFormat | Error::Corrupt | Error::InvalidGeometry => RpcError::Malformed,
            other => RpcError::Internal(String::from(other.code())),
        }
    }
}

/// Length-prefix a postcard encoding of `msg`: `u32 BE len` then the bytes.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(msg).map_err(|_| Error::InvalidFormat)?;
    if body.len() > MAX_RPC_FRAME {
        return Err(Error::BufferTooSmall { needed: body.len() });
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Read the length prefix; `Err(BufferTooSmall)` when it exceeds [`MAX_RPC_FRAME`].
pub fn frame_len(prefix: &[u8; 4]) -> Result<usize> {
    let n = u32::from_be_bytes(*prefix) as usize;
    if n > MAX_RPC_FRAME {
        return Err(Error::BufferTooSmall { needed: n });
    }
    Ok(n)
}

/// Decode a frame body (the bytes after the prefix).
pub fn decode_body<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T> {
    postcard::from_bytes(body).map_err(|_| Error::InvalidFormat)
}

/// Decode a whole frame (prefix + body); returns the message and the bytes consumed.
pub fn decode_frame<'a, T: Deserialize<'a>>(frame: &'a [u8]) -> Result<(T, usize)> {
    let prefix: &[u8; 4] = frame
        .get(..4)
        .ok_or(Error::InvalidFormat)?
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    let n = frame_len(prefix)?;
    let body = frame.get(4..4 + n).ok_or(Error::InvalidFormat)?;
    Ok((decode_body(body)?, 4 + n))
}

/// Who a verified request came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// The caller's DID, when an assertion verified.
    pub did: Option<Did>,
    /// True when `did` is the pinned owner.
    pub is_owner: bool,
}

/// The authorisation rule a device applies before dispatching:
///
/// - a [`Access::Public`] request passes with or without an assertion (an
///   invalid one is still rejected, so a caller cannot probe with junk);
/// - an [`Access::Owner`] request needs an assertion that verifies (see
///   [`Assertion::verify`]) **and** whose caller is the pinned owner's DID;
///   with no owner pinned yet, only [`Request::Adopt`] is allowed through so
///   the first owner can adopt (the adoption itself is then verified by
///   `rusty_esp_mid_core::adoption::Adoption::accept`).
pub fn authorize<const N: usize>(
    env: &Envelope,
    my_did: &str,
    pin: Option<&OwnerPin>,
    now: Option<u64>,
    window: &mut NonceWindow<N>,
) -> core::result::Result<Caller, RpcError> {
    let caller_did = match &env.assertion {
        Some(wire) => {
            let a = wire.as_assertion().map_err(|_| RpcError::Malformed)?;
            Some(a.verify(my_did, now, window)?)
        }
        None => None,
    };
    let owner_did = pin.and_then(|p| Did::from_pubkey(&p.genesis_pubkey).ok());
    let is_owner = matches!((caller_did, owner_did), (Some(c), Some(o)) if c == o);
    match env.request.access() {
        Access::Public => Ok(Caller {
            did: caller_did,
            is_owner,
        }),
        Access::Owner => {
            if caller_did.is_none() {
                return Err(RpcError::Unauthorized);
            }
            if is_owner || (owner_did.is_none() && matches!(env.request, Request::Adopt(_))) {
                Ok(Caller {
                    did: caller_did,
                    is_owner,
                })
            } else {
                Err(RpcError::Denied)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rusty_esp_mid_core::DeviceSigner;
    use rusty_esp_mid_core::key::DeviceKey;

    fn did_string(key: &DeviceKey) -> String {
        let mut buf = [0u8; 64];
        String::from(key.did().write(&mut buf).unwrap())
    }

    fn signed(caller: &DeviceKey, device: &DeviceKey, nonce: u8, request: Request) -> Envelope {
        let c = did_string(caller);
        let d = did_string(device);
        let n = [nonce; 32];
        let a = Assertion::sign(&c, &d, &n, 1_000, 60, caller).unwrap();
        Envelope {
            assertion: Some(WireAssertion::from_assertion(&a)),
            request,
        }
    }

    #[test]
    fn frames_round_trip_and_cap_size() {
        let env = Envelope {
            assertion: None,
            request: Request::Call {
                capability: String::from("gpio:set@led"),
                args: vec![1, 2, 3],
            },
        };
        let frame = encode_frame(&env).unwrap();
        let (back, used): (Envelope, usize) = decode_frame(&frame).unwrap();
        assert_eq!(back, env);
        assert_eq!(used, frame.len());
        let resp = Response::Manifest {
            bytes: vec![0xAA; 300],
            sig: vec![1; 64],
            did: String::from("did:mata:x"),
        };
        let f2 = encode_frame(&resp).unwrap();
        let (r2, _): (Response, usize) = decode_frame(&f2).unwrap();
        assert_eq!(r2, resp);
        assert_eq!(
            frame_len(&(MAX_RPC_FRAME as u32 + 1).to_be_bytes()).err(),
            Some(Error::BufferTooSmall {
                needed: MAX_RPC_FRAME + 1
            })
        );
        assert!(decode_frame::<Envelope>(&frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn unknown_variant_is_malformed_not_a_panic() {
        // postcard encodes an enum as its variant index; index 99 does not exist.
        let body = [99u8, 0, 0];
        assert!(decode_body::<Request>(&body).is_err());
        assert_eq!(RpcError::from(Error::InvalidFormat), RpcError::Malformed);
    }

    #[test]
    fn authorization_rule() {
        let owner = DeviceKey::from_seed_for_tests("owner", "hub");
        let stranger = DeviceKey::from_seed_for_tests("stranger", "x");
        let device = DeviceKey::from_seed_for_tests("device", "janus");
        let my = did_string(&device);
        let pin = OwnerPin {
            genesis_pubkey: *owner.did().pubkey(),
            roster_version: 1,
        };
        let mut w = NonceWindow::<16>::new();

        // Public without assertion.
        let ping = Envelope {
            assertion: None,
            request: Request::Ping,
        };
        assert_eq!(
            authorize(&ping, &my, Some(&pin), None, &mut w).unwrap().did,
            None
        );
        // Owner-only without assertion.
        let tele = Envelope {
            assertion: None,
            request: Request::Telemetry,
        };
        assert_eq!(
            authorize(&tele, &my, Some(&pin), None, &mut w).err(),
            Some(RpcError::Unauthorized)
        );
        // Stranger with a valid assertion: denied.
        let s = signed(&stranger, &device, 1, Request::Telemetry);
        assert_eq!(
            authorize(&s, &my, Some(&pin), None, &mut w).err(),
            Some(RpcError::Denied)
        );
        // Owner: allowed, and flagged.
        let o = signed(&owner, &device, 2, Request::Telemetry);
        let c = authorize(&o, &my, Some(&pin), None, &mut w).unwrap();
        assert!(c.is_owner);
        assert_eq!(c.did, Some(owner.did()));
        // Replay of the same nonce: denied.
        assert_eq!(
            authorize(&o, &my, Some(&pin), None, &mut w).err(),
            Some(RpcError::Denied)
        );
        // No pin yet: only Adopt passes for a stranger.
        let adopt = signed(&stranger, &device, 3, Request::Adopt(vec![0; 8]));
        assert!(authorize(&adopt, &my, None, None, &mut w).is_ok());
        let s2 = signed(&stranger, &device, 4, Request::Telemetry);
        assert_eq!(
            authorize(&s2, &my, None, None, &mut w).err(),
            Some(RpcError::Denied)
        );
        // A junk assertion on a public request is still rejected.
        let mut junk = signed(&owner, &device, 5, Request::Ping);
        junk.assertion.as_mut().unwrap().sig[0] ^= 1;
        assert_eq!(
            authorize(&junk, &my, Some(&pin), None, &mut w).err(),
            Some(RpcError::Denied)
        );
        let _ = device.sign_prehash(&[0; 32]);
    }
}
