//! The client: dial a Janus node by ticket and speak its four protocols.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use rusty_esp_iroh_core::alpn;
use rusty_esp_iroh_core::assertion::{Assertion, DEFAULT_TTL_SECS};
use rusty_esp_iroh_core::media::{HEADER_LEN, LossCounter, PacketHeader, Subscribe};
use rusty_esp_iroh_core::mid::did::MAX_DID_LEN;
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::esp_core::time::{Micros, WallOffset};
use rusty_esp_iroh_core::ota::{OtaManifest, CHUNK_LEN};
use rusty_esp_iroh_core::rpc::{self, Envelope, Request, Response, WireAssertion};
use rusty_esp_iroh_core::sidecar::RpcReply;
use rusty_esp_iroh_core::ticket::Ticket;

use crate::error::{HostError, Result};
use crate::now_unix;

/// A dialing endpoint, optionally with a caller identity for assertions.
pub struct Client {
    endpoint: Endpoint,
    caller: Option<DeviceKey>,
    /// Per-call timeout.
    pub timeout: Duration,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("endpoint_id", &self.endpoint.id())
            .field("has_caller", &self.caller.is_some())
            .finish()
    }
}

/// Turn a Janus ticket into the address iroh dials.
pub fn endpoint_addr(ticket: &Ticket) -> Result<EndpointAddr> {
    let id = EndpointId::from_bytes(&ticket.endpoint_id)
        .map_err(|e| HostError::Connect(format!("{e}")))?;
    let mut addr = EndpointAddr::new(id);
    for a in ticket.addrs() {
        addr = addr.with_ip_addr(a);
    }
    if let Some(relay) = ticket.relay() {
        let url: RelayUrl = relay
            .parse()
            .map_err(|e| HostError::Connect(format!("{e}")))?;
        addr = addr.with_relay_url(url);
    }
    Ok(addr)
}

impl Client {
    /// Bind a client endpoint. `secret` fixes the client's endpoint id
    /// (`None` = random); `caller` signs assertions (`None` = anonymous).
    pub async fn bind(
        secret: Option<SecretKey>,
        caller: Option<DeviceKey>,
        relay: bool,
    ) -> Result<Self> {
        let mut builder =
            Endpoint::builder(presets::Empty).crypto_provider(Arc::new(crate::crypto::provider()));
        builder = crate::configure_reach(builder, relay)?;
        if let Some(s) = secret {
            builder = builder.secret_key(s);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| HostError::Bind(format!("{e:?}")))?;
        Ok(Client {
            endpoint,
            caller,
            timeout: Duration::from_secs(10),
        })
    }

    /// The client's own endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The caller DID, when the client has a key.
    #[must_use]
    pub fn caller_did(&self) -> Option<String> {
        let key = self.caller.as_ref()?;
        let mut buf = [0u8; MAX_DID_LEN];
        key.did().write(&mut buf).ok().map(String::from)
    }

    async fn connect(&self, addr: &EndpointAddr, alpn: &[u8]) -> Result<Connection> {
        tokio::time::timeout(self.timeout, self.endpoint.connect(addr.clone(), alpn))
            .await
            .map_err(|_| HostError::Timeout)?
            .map_err(|e| HostError::Connect(format!("{e}")))
    }

    /// One bi-stream round trip: send `payload`, read the whole reply.
    async fn round_trip(
        &self,
        addr: &EndpointAddr,
        alpn: &[u8],
        payload: &[u8],
        max_reply: usize,
    ) -> Result<Vec<u8>> {
        let conn = self.connect(addr, alpn).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        send.write_all(payload)
            .await
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        send.finish()
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let reply = tokio::time::timeout(self.timeout, recv.read_to_end(max_reply))
            .await
            .map_err(|_| HostError::Timeout)?
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        Ok(reply)
    }

    /// `janus/echo/1`.
    pub async fn echo(&self, addr: &EndpointAddr, payload: &[u8]) -> Result<Vec<u8>> {
        self.round_trip(addr, alpn::ECHO, payload, alpn::MAX_RPC_FRAME)
            .await
    }

    /// Mint an assertion for `device_did` with the caller key, if any.
    fn assertion(&self, device_did: &str) -> Result<Option<WireAssertion>> {
        let Some(key) = &self.caller else {
            return Ok(None);
        };
        let caller_did = self.caller_did().ok_or(HostError::Protocol(
            rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
        ))?;
        let nonce: [u8; 32] = rand::random();
        let issued_at = now_unix().unwrap_or(1);
        let a = Assertion::sign(
            &caller_did,
            device_did,
            &nonce,
            issued_at,
            DEFAULT_TTL_SECS,
            key,
        )?;
        Ok(Some(WireAssertion::from_assertion(&a)))
    }

    /// `janus/rpc/1`: send `request` to the device with DID `device_did`,
    /// with an assertion when the client has a caller key.
    pub async fn rpc(
        &self,
        addr: &EndpointAddr,
        device_did: &str,
        request: Request,
    ) -> Result<Response> {
        let env = Envelope {
            assertion: self.assertion(device_did)?,
            request,
        };
        let frame = rpc::encode_frame(&env)?;
        let reply = self
            .round_trip(addr, alpn::RPC, &frame, alpn::MAX_RPC_FRAME + 4)
            .await?;
        let (response, _): (Response, usize) = rpc::decode_frame(&reply)?;
        Ok(response)
    }

    /// `janus/rpc/1` with no assertion regardless of the caller key.
    pub async fn rpc_anonymous(&self, addr: &EndpointAddr, request: Request) -> Result<Response> {
        let env = Envelope {
            assertion: None,
            request,
        };
        let frame = rpc::encode_frame(&env)?;
        let reply = self
            .round_trip(addr, alpn::RPC, &frame, alpn::MAX_RPC_FRAME + 4)
            .await?;
        let (response, _): (Response, usize) = rpc::decode_frame(&reply)?;
        Ok(response)
    }

    /// The host's one-shot device→wall mapping (C2): wall clock before and
    /// after `Request::Time`, the device reading placed mid round trip.
    pub async fn time(&self, addr: &EndpointAddr) -> Result<WallOffset> {
        let t0 = now_unix_micros();
        let response = self.rpc_anonymous(addr, Request::Time).await?;
        let t1 = now_unix_micros();
        match response {
            Response::Time { device_us } => {
                WallOffset::from_exchange(t0, Micros(device_us), t1).map_err(HostError::Protocol)
            }
            Response::Error(e) => Err(HostError::Rpc(e)),
            _ => Err(HostError::Protocol(
                rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
            )),
        }
    }

    /// Push a maker-signed image over `janus/ota/1` as the owner: the
    /// envelope first, then — only after the device answered `OtaReady` —
    /// the bytes in [`CHUNK_LEN`] pieces, then the device's verdict.
    pub async fn ota(
        &self,
        addr: &EndpointAddr,
        device_did: &str,
        manifest: &OtaManifest,
        image: &[u8],
    ) -> Result<OtaOutcome> {
        if image.len() != manifest.image_len as usize {
            return Err(HostError::Protocol(
                rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
            ));
        }
        let env = Envelope {
            assertion: self.assertion(device_did)?,
            request: Request::Ota(manifest.clone()),
        };
        let conn = self.connect(addr, alpn::OTA).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let frame = rpc::encode_frame(&env)?;
        send.write_all(&frame)
            .await
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let first = self.read_frame(&mut recv).await?;
        match first {
            Response::OtaReady => {}
            Response::Error(e) => return Ok(OtaOutcome::Refused(e)),
            _ => {
                return Err(HostError::Protocol(
                    rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
                ))
            }
        }
        for chunk in image.chunks(CHUNK_LEN) {
            send.write_all(chunk)
                .await
                .map_err(|e| HostError::Stream(format!("{e}")))?;
        }
        send.finish()
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let verdict = self.read_frame(&mut recv).await?;
        match verdict {
            Response::OtaResult { firmware, sha256 } => Ok(OtaOutcome::Committed { firmware, sha256 }),
            Response::Error(e) => Ok(OtaOutcome::Refused(e)),
            _ => Err(HostError::Protocol(
                rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
            )),
        }
    }

    /// One length-prefixed response frame off a stream that stays open.
    async fn read_frame(&self, recv: &mut iroh::endpoint::RecvStream) -> Result<Response> {
        let mut prefix = [0u8; 4];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut prefix))
            .await
            .map_err(|_| HostError::Timeout)?
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let n = rpc::frame_len(&prefix)?;
        let mut body = vec![0u8; n];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut body))
            .await
            .map_err(|_| HostError::Timeout)?
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        rpc::decode_body(&body).map_err(HostError::from)
    }

    /// `mata-oem-sidecar/rpc/1`: send a JSON request such as `{"op":"ping"}`.
    pub async fn sidecar(&self, addr: &EndpointAddr, request_json: &str) -> Result<RpcReply> {
        let reply = self
            .round_trip(
                addr,
                alpn::SIDECAR_RPC,
                request_json.as_bytes(),
                alpn::MAX_SIDECAR_BYTES,
            )
            .await?;
        serde_json::from_slice(&reply).map_err(|e| HostError::Json(format!("{e}")))
    }

    /// `janus/media/1`: subscribe and receive up to `max_packets` packets or
    /// until `for_at_most` elapses, calling `on_packet` for each. Returns the
    /// loss counter.
    pub async fn subscribe(
        &self,
        addr: &EndpointAddr,
        sub: &Subscribe,
        max_packets: u64,
        for_at_most: Duration,
        mut on_packet: impl FnMut(&PacketHeader, &[u8]),
    ) -> Result<LossCounter> {
        let conn = self.connect(addr, alpn::MEDIA).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let frame = rpc::encode_frame(sub)?;
        send.write_all(&frame)
            .await
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        send.finish()
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let ack = tokio::time::timeout(self.timeout, recv.read_to_end(alpn::MAX_RPC_FRAME))
            .await
            .map_err(|_| HostError::Timeout)?
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let (_echoed, _): (Subscribe, usize) = rpc::decode_frame(&ack)?;

        let mut counter = LossCounter::default();
        let deadline = tokio::time::sleep(for_at_most);
        tokio::pin!(deadline);
        let mut handle = |bytes: &[u8], counter: &mut LossCounter| {
            if let Ok(h) = PacketHeader::parse(bytes) {
                counter.observe(&h);
                on_packet(&h, &bytes[HEADER_LEN..]);
            }
        };
        while counter.received < max_packets {
            tokio::select! {
                () = &mut deadline => break,
                d = conn.read_datagram() => match d {
                    Ok(bytes) => handle(&bytes, &mut counter),
                    Err(_) => break,
                },
                u = conn.accept_uni() => match u {
                    Ok(mut uni) => {
                        if let Ok(bytes) = uni.read_to_end(alpn::MAX_MEDIA_PACKET).await {
                            handle(&bytes, &mut counter);
                        }
                    }
                    Err(_) => break,
                },
            }
        }
        Ok(counter)
    }

    /// Close the endpoint.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// What the device said to an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtaOutcome {
    /// The image is in the boot slot; the device reports `firmware` after it boots.
    Committed {
        /// The manifest's firmware string.
        firmware: String,
        /// The digest the device computed.
        sha256: [u8; 32],
    },
    /// Refused, at the named check.
    Refused(rusty_esp_iroh_core::rpc::RpcError),
}

/// Unix microseconds now (0 before the clock is set).
fn now_unix_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
