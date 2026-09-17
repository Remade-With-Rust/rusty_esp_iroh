//! The client: dial a Janus node by ticket and speak its four protocols.

use std::sync::Arc;
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey};
use rusty_esp_iroh_core::alpn;
use rusty_esp_iroh_core::assertion::{Assertion, DEFAULT_TTL_SECS};
use rusty_esp_iroh_core::esp_core::time::{Micros, WallOffset};
use rusty_esp_iroh_core::media::{HEADER_LEN, LossCounter, PacketHeader, Subscribe};
use rusty_esp_iroh_core::mid::did::MAX_DID_LEN;
use rusty_esp_iroh_core::mid::key::DeviceKey;
use rusty_esp_iroh_core::ota::{CHUNK_LEN, OtaManifest};
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

    /// `Request::Manifest`, then the signature checked under the DID the
    /// device claims (the DID carries the key) and the bytes parsed. What an
    /// adoption loop calls before it trusts a single capability.
    pub async fn manifest(&self, addr: &EndpointAddr) -> Result<VerifiedManifest> {
        use rusty_esp_iroh_core::esp_core::error::Error;
        match self.rpc_anonymous(addr, Request::Manifest).await? {
            Response::Manifest { bytes, sig, did } => {
                let sig: [u8; 64] = sig
                    .as_slice()
                    .try_into()
                    .map_err(|_| HostError::Protocol(Error::InvalidFormat))?;
                let did_obj =
                    rusty_esp_iroh_core::mid::did::Did::parse(&did).map_err(HostError::Protocol)?;
                rusty_esp_iroh_core::mid::manifest::verify_manifest(&bytes, &sig, did_obj.pubkey())
                    .map_err(|_| HostError::Protocol(Error::Crypto))?;
                let parsed =
                    rusty_esp_iroh_core::esp_core::capability::ParsedManifest::parse(&bytes)
                        .map_err(HostError::Protocol)?;
                Ok(VerifiedManifest {
                    did,
                    bytes,
                    sig,
                    parsed,
                })
            }
            Response::Error(e) => Err(HostError::Rpc(e)),
            _ => Err(HostError::Protocol(Error::InvalidFormat)),
        }
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
        let started = std::time::Instant::now();
        let first = self
            .read_frame_within(&mut recv, self.timeout)
            .await
            .map_err(|e| ota_stage(e, "the device's OtaReady", 0, started))?;
        match first {
            Response::OtaReady => {}
            Response::Error(e) => return Ok(OtaOutcome::Refused(e)),
            _ => {
                return Err(HostError::Protocol(
                    rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
                ));
            }
        }
        let mut sent = 0usize;
        for chunk in image.chunks(CHUNK_LEN) {
            send.write_all(chunk)
                .await
                .map_err(|e| ota_stage(HostError::Stream(format!("{e}")), "a chunk", sent, started))?;
            sent += chunk.len();
        }
        send.finish()
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        // A QUIC write completes when the bytes are accepted, not received:
        // the device may still be writing megabytes to flash when the last
        // chunk is "sent". The verdict's patience fits the image -- 30 s
        // plus a second per 50 KB, 110 s for a 4 MB image -- because the
        // second attempt of Run 4 (2026-09-16) gave up after 10 s.
        let patience = Duration::from_secs(30 + u64::from(manifest.image_len) / 50_000);
        let verdict = self
            .read_frame_within(&mut recv, patience)
            .await
            .map_err(|e| ota_stage(e, "the verdict", sent, started))?;
        match verdict {
            Response::OtaResult { firmware, sha256 } => {
                Ok(OtaOutcome::Committed { firmware, sha256 })
            }
            Response::Error(e) => Ok(OtaOutcome::Refused(e)),
            _ => Err(HostError::Protocol(
                rusty_esp_iroh_core::esp_core::error::Error::InvalidFormat,
            )),
        }
    }

    /// One length-prefixed response frame off a stream that stays open,
    /// within `patience`.
    async fn read_frame_within(
        &self,
        recv: &mut iroh::endpoint::RecvStream,
        patience: Duration,
    ) -> Result<Response> {
        let mut prefix = [0u8; 4];
        tokio::time::timeout(patience, recv.read_exact(&mut prefix))
            .await
            .map_err(|_| HostError::Timeout)?
            .map_err(|e| HostError::Stream(format!("{e}")))?;
        let n = rpc::frame_len(&prefix)?;
        let mut body = vec![0u8; n];
        tokio::time::timeout(patience, recv.read_exact(&mut body))
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

    /// Bytes on one bi-stream of `alpn`, the whole reply back, nothing
    /// encoded by this side: what an abuse test sends.
    pub async fn send_raw(
        &self,
        addr: &EndpointAddr,
        alpn: &[u8],
        payload: &[u8],
        max_reply: usize,
    ) -> Result<Vec<u8>> {
        self.round_trip(addr, alpn, payload, max_reply).await
    }

    /// Random bytes on every ALPN the node speaks: `rounds` streams per
    /// ALPN cycling through eight shapes (empty; one byte; a length prefix
    /// nothing could satisfy; one over the frame cap; one byte short of its
    /// own prefix; 1,500 random; 64 KB random; a well-formed prefix with a
    /// garbage body), then three garbage datagrams on a media connection.
    /// The report says what became of each attempt -- answered, or refused
    /// or dropped -- and neither is a verdict: whether the node still
    /// answers is the caller's ping afterwards. `seed` fixes the bytes.
    pub async fn garbage(&self, addr: &EndpointAddr, rounds: u32, seed: u64) -> GarbageReport {
        let mut lcg = Lcg(seed | 1);
        let mut report = GarbageReport::default();
        for alpn in alpn::ALL {
            let mut a = AlpnGarbage {
                alpn: String::from_utf8_lossy(alpn).into_owned(),
                ..AlpnGarbage::default()
            };
            for round in 0..rounds {
                let payload = garbage_shape(round, &mut lcg);
                a.sent += 1;
                let attempt = tokio::time::timeout(
                    GARBAGE_PATIENCE,
                    self.round_trip(addr, alpn, &payload, alpn::MAX_MEDIA_PACKET),
                )
                .await;
                match attempt {
                    Ok(Ok(_)) => a.answered += 1,
                    _ => a.errors += 1,
                }
            }
            report.per_alpn.push(a);
        }
        if let Ok(conn) = self.connect(addr, alpn::MEDIA).await {
            for _ in 0..3 {
                let bytes = lcg.bytes(64);
                if conn.send_datagram(bytes.into()).is_ok() {
                    report.datagrams += 1;
                }
            }
        }
        report
    }

    /// `level` media subscriptions at once, each on its own connection,
    /// each held for `hold`. `ok` counts the ones the node accepted and
    /// served at least one packet; `failed` the rest. One level, measured;
    /// the caller ramps and pings between levels, because where a board
    /// stops is a number to find, not a limit to assume.
    pub async fn flood(&self, addr: &EndpointAddr, level: usize, hold: Duration) -> FloodReport {
        let sub = Subscribe {
            codec: *b"any ",
            max_fps: 0,
            max_kbps: 0,
        };
        let futs: Vec<_> = (0..level)
            .map(|_| Box::pin(self.subscribe(addr, &sub, u64::MAX, hold, |_, _| {})))
            .collect();
        let mut report = FloodReport::default();
        for result in join_all(futs).await {
            match result {
                Ok(counter) if counter.received > 0 => report.ok += 1,
                _ => report.failed += 1,
            }
        }
        report
    }

    /// Close the endpoint.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// How long a garbage stream is given to be answered or dropped before it
/// counts as dropped and the next one is sent.
const GARBAGE_PATIENCE: Duration = Duration::from_secs(3);

/// What one ALPN did with garbage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlpnGarbage {
    /// The ALPN as text.
    pub alpn: String,
    /// Streams opened.
    pub sent: u32,
    /// Streams that got any reply before a clean end.
    pub answered: u32,
    /// Streams refused, reset, or left unanswered within the patience.
    pub errors: u32,
}

/// What [`Client::garbage`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GarbageReport {
    /// One entry per ALPN, in [`alpn::ALL`] order.
    pub per_alpn: Vec<AlpnGarbage>,
    /// Garbage datagrams sent on a media connection.
    pub datagrams: u32,
}

impl GarbageReport {
    /// Streams opened across every ALPN.
    #[must_use]
    pub fn sent(&self) -> u32 {
        self.per_alpn.iter().map(|a| a.sent).sum()
    }

    /// Streams answered across every ALPN.
    #[must_use]
    pub fn answered(&self) -> u32 {
        self.per_alpn.iter().map(|a| a.answered).sum()
    }

    /// Streams refused or dropped across every ALPN.
    #[must_use]
    pub fn errors(&self) -> u32 {
        self.per_alpn.iter().map(|a| a.errors).sum()
    }
}

/// What one level of [`Client::flood`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FloodReport {
    /// Subscriptions accepted and served at least one packet.
    pub ok: u32,
    /// Subscriptions refused, timed out, or served nothing.
    pub failed: u32,
}

/// A fixed-sequence generator, so a garbage run is the same bytes on every
/// machine and a failure can be replayed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u32
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// The eight shapes of garbage, one per round modulo eight.
fn garbage_shape(round: u32, lcg: &mut Lcg) -> Vec<u8> {
    let with_prefix = |len: u32, body: Vec<u8>| {
        let mut v = len.to_be_bytes().to_vec();
        v.extend(body);
        v
    };
    match round % 8 {
        0 => Vec::new(),
        1 => vec![lcg.next() as u8],
        2 => with_prefix(u32::MAX, Vec::new()),
        3 => with_prefix(alpn::MAX_RPC_FRAME as u32 + 1, lcg.bytes(8)),
        4 => with_prefix(64, lcg.bytes(63)),
        5 => lcg.bytes(1500),
        6 => lcg.bytes(alpn::MAX_RPC_FRAME + 64),
        _ => with_prefix(8, lcg.bytes(8)),
    }
}

/// Every future to completion, on one task, no extra crate.
async fn join_all<F: Future + Unpin>(mut futs: Vec<F>) -> Vec<F::Output> {
    let mut out: Vec<Option<F::Output>> = (0..futs.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (slot, fut) in out.iter_mut().zip(futs.iter_mut()) {
            if slot.is_none() {
                match Pin::new(fut).poll(cx) {
                    Poll::Ready(v) => *slot = Some(v),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending { Poll::Pending } else { Poll::Ready(()) }
    })
    .await;
    out.into_iter().flatten().collect()
}

/// A timeout or a stream error during an update, with the stage it
/// happened at and how far the push had got: "Timeout" alone cost a trip.
fn ota_stage(e: HostError, stage: &str, sent: usize, started: std::time::Instant) -> HostError {
    match e {
        HostError::Timeout => HostError::Stream(format!(
            "timed out waiting for {stage} after {:.1} s with {sent} bytes sent",
            started.elapsed().as_secs_f64()
        )),
        HostError::Stream(s) => HostError::Stream(format!(
            "{s} (at {stage}, after {:.1} s with {sent} bytes sent)",
            started.elapsed().as_secs_f64()
        )),
        other => other,
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

/// A device's manifest as fetched over `janus/rpc/1`, its signature already
/// verified under the device's DID, its bytes kept for anyone who wants to
/// verify again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    /// The device DID the signature verified under.
    pub did: String,
    /// The canonical bytes, exactly as received.
    pub bytes: Vec<u8>,
    /// The device's signature over `bytes`.
    pub sig: [u8; 64],
    /// The bytes, read.
    pub parsed: rusty_esp_iroh_core::esp_core::capability::ParsedManifest,
}
