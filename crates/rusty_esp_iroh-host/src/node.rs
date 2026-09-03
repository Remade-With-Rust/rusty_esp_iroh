//! A Janus node: one iroh endpoint, four ALPNs.
//!
//! - `janus/echo/1`: bytes back.
//! - `janus/rpc/1`: one postcard frame in, one out; the authorisation rule of
//!   [`rusty_esp_iroh_core::rpc::authorize`] gates every request; `Adopt`
//!   installs the owner pin through `rusty_esp_mid`.
//! - `janus/media/1`: a subscribe frame, then packets from a [`MediaSource`]
//!   as datagrams or uni-streams.
//! - `mata-oem-sidecar/rpc/1`: the home computer's JSON RPC.
//!
//! The node is `std` and runs unchanged on the host and on ESP-IDF; what a
//! chip adds (NVS, Wi-Fi, SNTP, mDNS) lives in `rusty_esp_iroh-esp`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use iroh::endpoint::presets;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use rusty_esp_iroh_core::alpn;
use rusty_esp_iroh_core::esp_core::capability::Manifest;
use rusty_esp_iroh_core::esp_core::hal::Kv;
use rusty_esp_iroh_core::media::{HEADER_LEN, PacketHeader, Subscribe};
use rusty_esp_iroh_core::mid::adoption::{Adoption, KV_ADOPTION, KV_OWNER_PIN, OwnerPin};
use rusty_esp_iroh_core::mid::manifest::sign_manifest_bytes;
use rusty_esp_iroh_core::mid::nonce::NonceWindow;
use rusty_esp_iroh_core::ota::{CHUNK_LEN, OtaManifest, OtaSession, OtaSink, Refusal};
use rusty_esp_iroh_core::rpc::NeighbourInfo;
use rusty_esp_iroh_core::rpc::{self, Envelope, Request, Response, RpcError, Telemetry};
use rusty_esp_iroh_core::sidecar::{self, DeviceInfo, PairState, Tier};
use rusty_esp_iroh_core::ticket::{MAX_TEXT_LEN, Ticket};

use crate::error::{HostError, Result};
use crate::identity::NodeIdentity;
use crate::now_unix;

/// How the node binds.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Use n0's relays and pkarr lookup (the PSRAM tier); off = LAN-direct only.
    pub relay: bool,
    /// `model=` for the sidecar advertisement and status, e.g. `janus/camera`.
    pub model: String,
    /// Firmware identifier.
    pub firmware: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            relay: false,
            model: String::from("janus/node"),
            firmware: format!("rusty_esp_iroh {}", rusty_esp_iroh_core::VERSION),
        }
    }
}

/// What a node answers about the devices it fronts (a bridge).
pub trait NeighbourSource: Send + Sync {
    /// Every neighbour with a verified manifest, as the wire form.
    fn neighbours(&self) -> Vec<NeighbourInfo>;
}

/// The optional seams a node may be bound with: the maker it trusts for
/// OTA and the slot the image goes to, and the neighbour table a bridge
/// answers `Request::Neighbours` from. All absent by default.
#[derive(Default)]
pub struct Extras {
    /// The maker DID whose signature an OTA manifest must carry.
    pub maker_did: Option<String>,
    /// Where an accepted image is written (`MemorySlots` on the host,
    /// `esp-ota` on the chip). Without it `janus/ota/1` is `Unsupported`.
    pub ota: Option<Box<dyn OtaSink + Send>>,
    /// The neighbours a bridge fronts.
    pub neighbours: Option<Arc<dyn NeighbourSource>>,
}

impl core::fmt::Debug for Extras {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Extras")
            .field("maker_did", &self.maker_did)
            .field("ota", &self.ota.is_some())
            .field("neighbours", &self.neighbours.is_some())
            .finish()
    }
}

/// Produces media packets for one subscriber.
pub trait MediaSource: Send {
    /// The next packet, or `None` when the stream is over.
    fn next_packet(&mut self) -> Option<(PacketHeader, Vec<u8>)>;
    /// How long to wait between packets.
    fn interval(&self) -> Duration;
}

/// Makes a fresh [`MediaSource`] per subscriber.
pub type MediaFactory = Arc<dyn Fn(&Subscribe) -> Box<dyn MediaSource> + Send + Sync>;

/// Everything the handlers share.
pub struct DeviceState {
    identity: NodeIdentity,
    manifest: Vec<u8>,
    manifest_sig: [u8; 64],
    did: String,
    config: NodeConfig,
    kv: Mutex<Box<dyn Kv + Send>>,
    pin: Mutex<Option<OwnerPin>>,
    window: Mutex<NonceWindow<64>>,
    ticket_text: Mutex<String>,
    started: std::time::Instant,
    maker_did: Option<String>,
    /// `None`: no slot configured. `Some(None)`: an update is in progress
    /// and holds the slot. `Some(Some(_))`: idle.
    ota: Option<Mutex<Option<Box<dyn OtaSink + Send>>>>,
    last_ota: Mutex<Option<String>>,
    neighbours: Option<Arc<dyn NeighbourSource>>,
    /// Counters, for the ledger.
    pub counters: Counters,
}

/// What the node has seen. 32-bit on purpose: Xtensa has no 64-bit atomics
/// (see `rusty_esp_core::time`), and four billion of anything is enough for a
/// counter that is read every few seconds.
#[derive(Debug, Default)]
pub struct Counters {
    /// Echo connections served.
    pub echo: AtomicU32,
    /// RPC requests answered (any outcome).
    pub rpc: AtomicU32,
    /// RPC requests refused (`Unauthorized` or `Denied`).
    pub rpc_refused: AtomicU32,
    /// Sidecar requests answered.
    pub sidecar: AtomicU32,
    /// Media subscribers served.
    pub media_subscribers: AtomicU32,
    /// Media packets sent.
    pub media_packets: AtomicU32,
    /// Media packets that could not be sent.
    pub media_send_errors: AtomicU32,
    /// Images accepted into the boot slot.
    pub ota_committed: AtomicU32,
    /// Updates refused, at any check.
    pub ota_refused: AtomicU32,
}

impl DeviceState {
    fn pin(&self) -> Option<OwnerPin> {
        *self.pin.lock().expect("pin lock")
    }

    fn set_pin(&self, pin: OwnerPin, adoption_bytes: &[u8]) -> core::result::Result<(), RpcError> {
        let mut enc = [0u8; OwnerPin::LEN];
        pin.encode(&mut enc).map_err(RpcError::from)?;
        let mut kv = self.kv.lock().expect("kv lock");
        kv.put(KV_OWNER_PIN, &enc).map_err(RpcError::from)?;
        kv.put(KV_ADOPTION, adoption_bytes)
            .map_err(RpcError::from)?;
        *self.pin.lock().expect("pin lock") = Some(pin);
        Ok(())
    }

    /// The authorisation rule, counted.
    fn authorize(&self, env: &Envelope) -> core::result::Result<rpc::Caller, RpcError> {
        let now = now_unix();
        let mut window = self.window.lock().expect("window lock");
        rpc::authorize(env, &self.did, self.pin().as_ref(), now, &mut window).inspect_err(|_| {
            self.counters.rpc_refused.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Every check an OTA manifest must pass before a byte is accepted.
    fn ota_admit(&self, manifest: &OtaManifest) -> core::result::Result<(), Refusal> {
        let parsed =
            rusty_esp_iroh_core::esp_core::capability::ParsedManifest::parse(&self.manifest)
                .map_err(|_| Refusal::NoOtaCapability)?;
        if !parsed.has(rusty_esp_iroh_core::esp_core::capability::Capability::Ota) {
            return Err(Refusal::NoOtaCapability);
        }
        manifest.verify(parsed.chip, &self.config.model, self.maker_did.as_deref())
    }

    fn dispatch(&self, env: Envelope) -> Response {
        let now = now_unix();
        let caller = match self.authorize(&env) {
            Ok(c) => c,
            Err(e) => return Response::Error(e),
        };
        match env.request {
            Request::Ping => Response::Pong,
            Request::Manifest => Response::Manifest {
                bytes: self.manifest.clone(),
                sig: self.manifest_sig.to_vec(),
                did: self.did.clone(),
            },
            Request::Telemetry => Response::Telemetry(Telemetry {
                uptime_us: self.started.elapsed().as_micros() as u64,
                heap_free: 0,
                heap_min: 0,
                rssi_dbm: 0,
                fw: self.config.firmware.clone(),
            }),
            Request::Adopt(bytes) => {
                let adoption = match Adoption::decode(&bytes) {
                    Ok(a) => a,
                    Err(e) => return Response::Error(e.into()),
                };
                // The caller must be the owner named in the adoption.
                let owner_matches = caller
                    .did
                    .map(|d| d.pubkey() == adoption.fields.owner_genesis_pubkey)
                    .unwrap_or(false);
                if !owner_matches {
                    self.counters.rpc_refused.fetch_add(1, Ordering::Relaxed);
                    return Response::Error(RpcError::Denied);
                }
                match adoption.accept(&self.did, self.pin().as_ref(), now) {
                    Ok(pin) => match self.set_pin(pin, &bytes) {
                        Ok(()) => Response::Adopted {
                            roster_version: pin.roster_version,
                        },
                        Err(e) => Response::Error(e),
                    },
                    Err(e) => {
                        self.counters.rpc_refused.fetch_add(1, Ordering::Relaxed);
                        Response::Error(e.into())
                    }
                }
            }
            Request::Call { .. } => Response::Error(RpcError::Unsupported),
            Request::Ticket => {
                Response::Ticket(self.ticket_text.lock().expect("ticket lock").clone())
            }
            Request::Time => Response::Time {
                device_us: self.started.elapsed().as_micros() as u64,
            },
            // The image rides its own ALPN; here the envelope has no bytes behind it.
            Request::Ota(_) => Response::Error(RpcError::Unsupported),
            Request::Neighbours => match &self.neighbours {
                Some(table) => Response::Neighbours(table.neighbours()),
                None => Response::Error(RpcError::Unsupported),
            },
        }
    }

    fn sidecar_info<'a>(
        &'a self,
        node_id: &'a str,
        direct: &'a [&'a str],
        uuid: &'a str,
    ) -> DeviceInfo<'a> {
        DeviceInfo {
            did: &self.did,
            model: &self.config.model,
            box_device_id: uuid,
            pair_state: if self.pin().is_some() {
                PairState::Paired
            } else {
                PairState::Open
            },
            tier: Tier::BestEffort,
            maker_did: None,
            fw: &self.config.firmware,
            iroh_node_id: Some(node_id),
            direct_addrs: direct,
            relay_urls: &[],
        }
    }
}

/// A running node.
pub struct Node {
    endpoint: Endpoint,
    router: Router,
    state: Arc<DeviceState>,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("did", &self.state.did)
            .field("endpoint_id", &self.endpoint.id())
            .finish_non_exhaustive()
    }
}

impl Node {
    /// Bind the endpoint and start serving. `kv` is where the adoption lands;
    /// `manifest` is signed once with the device key; `media` makes a source
    /// per subscriber (or `None` to refuse media).
    pub async fn bind(
        identity: NodeIdentity,
        kv: Box<dyn Kv + Send>,
        manifest: &Manifest<'_>,
        media: Option<MediaFactory>,
        config: NodeConfig,
    ) -> Result<Self> {
        Self::bind_with(identity, kv, manifest, media, config, Extras::default()).await
    }

    /// [`Node::bind`] with the optional seams: the trusted maker and the OTA
    /// slot, the neighbour table.
    pub async fn bind_with(
        identity: NodeIdentity,
        kv: Box<dyn Kv + Send>,
        manifest: &Manifest<'_>,
        media: Option<MediaFactory>,
        config: NodeConfig,
        extras: Extras,
    ) -> Result<Self> {
        let mut manifest_bytes = vec![0u8; manifest.encoded_len()];
        let n = manifest.encode(&mut manifest_bytes)?;
        manifest_bytes.truncate(n);
        let manifest_sig = sign_manifest_bytes(&manifest_bytes, &identity.device);

        // A pin already in the store (a rebooted device) is honoured.
        let mut pin_buf = [0u8; OwnerPin::LEN];
        let pin = match kv.get(KV_OWNER_PIN, &mut pin_buf)? {
            Some(OwnerPin::LEN) => Some(OwnerPin::decode(&pin_buf)?),
            _ => None,
        };

        let builder = Endpoint::builder(presets::Empty)
            .crypto_provider(Arc::new(crate::crypto::provider()))
            .secret_key(identity.endpoint.clone())
            .alpns(alpn::ALL.iter().map(|a| a.to_vec()).collect());
        let builder = crate::configure_reach(builder, config.relay)?;
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| HostError::Bind(format!("{e:?}")))?;

        let did = identity.did_string();
        let state = Arc::new(DeviceState {
            identity,
            manifest: manifest_bytes,
            manifest_sig,
            did,
            config,
            kv: Mutex::new(kv),
            pin: Mutex::new(pin),
            window: Mutex::new(NonceWindow::new()),
            ticket_text: Mutex::new(String::new()),
            started: std::time::Instant::now(),
            maker_did: extras.maker_did,
            ota: extras.ota.map(|sink| Mutex::new(Some(sink))),
            last_ota: Mutex::new(None),
            neighbours: extras.neighbours,
            counters: Counters::default(),
        });

        let router = Router::builder(endpoint.clone())
            .accept(alpn::ECHO, Echo(state.clone()))
            .accept(alpn::RPC, Rpc(state.clone()))
            .accept(alpn::SIDECAR_RPC, Sidecar(state.clone()))
            .accept(alpn::OTA, Ota(state.clone()))
            .accept(
                alpn::MEDIA,
                Media {
                    state: state.clone(),
                    factory: media,
                },
            )
            .spawn();

        let node = Node {
            endpoint,
            router,
            state,
        };
        node.refresh_ticket(&[]);
        Ok(node)
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The firmware string of the last image accepted into the boot slot,
    /// if any; on a chip the node reboots into it instead.
    #[must_use]
    pub fn last_ota(&self) -> Option<String> {
        self.state.last_ota.lock().expect("last ota").clone()
    }

    /// The device DID as text.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.state.did
    }

    /// The shared state (counters, identity).
    #[must_use]
    pub fn state(&self) -> &Arc<DeviceState> {
        &self.state
    }

    /// The identity.
    #[must_use]
    pub fn identity(&self) -> &NodeIdentity {
        &self.state.identity
    }

    /// The UDP port the endpoint bound.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.endpoint
            .bound_sockets()
            .first()
            .map_or(0, SocketAddr::port)
    }

    /// Build the rendezvous ticket: endpoint id, DID, and `ips` (each paired
    /// with the bound port) as direct addresses. Also stored for
    /// `Request::Ticket` and the sidecar.
    pub fn refresh_ticket(&self, ips: &[IpAddr]) -> Ticket {
        let mut t =
            Ticket::short(*self.endpoint.id().as_bytes()).with_did(self.state.identity.did());
        let port = self.port();
        for ip in ips.iter().take(rusty_esp_iroh_core::ticket::MAX_ADDRS) {
            if let Ok(next) = t.with_addr(SocketAddr::new(*ip, port)) {
                t = next;
            }
        }
        let mut buf = [0u8; MAX_TEXT_LEN];
        if let Ok(text) = t.write_text(&mut buf) {
            *self.state.ticket_text.lock().expect("ticket lock") = String::from(text);
        }
        t
    }

    /// The current ticket text.
    #[must_use]
    pub fn ticket_text(&self) -> String {
        self.state.ticket_text.lock().expect("ticket lock").clone()
    }

    /// The mDNS TXT record for `_mata-oem-sidecar._tcp.local.`, with `ips`
    /// as `iroh_direct`.
    #[must_use]
    pub fn sidecar_txt(&self, ips: &[IpAddr]) -> Vec<(String, String)> {
        let node_id = self.endpoint.id().to_string();
        let port = self.port();
        let direct: Vec<String> = ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, port).to_string())
            .collect();
        let direct_refs: Vec<&str> = direct.iter().map(String::as_str).collect();
        let uuid = sidecar::device_uuid(&self.state.did);
        sidecar::txt_record(&self.state.sidecar_info(&node_id, &direct_refs, &uuid))
    }

    /// Whether an owner is pinned.
    #[must_use]
    pub fn is_adopted(&self) -> bool {
        self.state.pin().is_some()
    }

    /// Stop serving and close the endpoint.
    pub async fn shutdown(self) {
        let _ = self.router.shutdown().await;
        self.endpoint.close().await;
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Echo(Arc<DeviceState>);

impl core::fmt::Debug for Echo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Echo")
    }
}

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        self.0.counters.echo.fetch_add(1, Ordering::Relaxed);
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes = recv
            .read_to_end(alpn::MAX_RPC_FRAME)
            .await
            .map_err(AcceptError::from_err)?;
        send.write_all(&bytes)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[derive(Clone)]
struct Rpc(Arc<DeviceState>);

impl core::fmt::Debug for Rpc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rpc")
    }
}

impl ProtocolHandler for Rpc {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let mut prefix = [0u8; 4];
        recv.read_exact(&mut prefix)
            .await
            .map_err(AcceptError::from_err)?;
        let response = match rpc::frame_len(&prefix) {
            Ok(n) => {
                let mut body = vec![0u8; n];
                recv.read_exact(&mut body)
                    .await
                    .map_err(AcceptError::from_err)?;
                match rpc::decode_body::<Envelope>(&body) {
                    Ok(env) => self.0.dispatch(env),
                    Err(_) => Response::Error(RpcError::Malformed),
                }
            }
            Err(_) => Response::Error(RpcError::Malformed),
        };
        self.0.counters.rpc.fetch_add(1, Ordering::Relaxed);
        let frame = rpc::encode_frame(&response).map_err(AcceptError::from_err)?;
        send.write_all(&frame)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[derive(Clone)]
struct Ota(Arc<DeviceState>);

impl core::fmt::Debug for Ota {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ota")
    }
}

impl Ota {
    fn refuse(&self, r: Refusal) -> Response {
        self.0.counters.ota_refused.fetch_add(1, Ordering::Relaxed);
        Response::Error(RpcError::Refused(format!("{r:?}")))
    }
}

impl ProtocolHandler for Ota {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let mut prefix = [0u8; 4];
        recv.read_exact(&mut prefix)
            .await
            .map_err(AcceptError::from_err)?;
        let n = rpc::frame_len(&prefix).map_err(AcceptError::from_err)?;
        let mut body = vec![0u8; n];
        recv.read_exact(&mut body)
            .await
            .map_err(AcceptError::from_err)?;
        let frame_of = |r: &Response| rpc::encode_frame(r).map_err(AcceptError::from_err);
        // 1. the envelope: authorised as any owner-only request, then every
        //    manifest check, all before a byte of image
        let admitted: core::result::Result<OtaManifest, Response> =
            match rpc::decode_body::<Envelope>(&body) {
                Err(_) => Err(Response::Error(RpcError::Malformed)),
                Ok(env) => match self.0.authorize(&env) {
                    Err(e) => Err(Response::Error(e)),
                    Ok(_) => match env.request {
                        Request::Ota(m) => match self.0.ota_admit(&m) {
                            Ok(()) => Ok(m),
                            Err(r) => Err(self.refuse(r)),
                        },
                        _ => Err(Response::Error(RpcError::Malformed)),
                    },
                },
            };
        let response = match admitted {
            Err(r) => r,
            Ok(manifest) => {
                // 2. the slot, taken out of the state for the duration so no
                //    lock is held across the stream reads
                let taken = match &self.0.ota {
                    None => Err(Response::Error(RpcError::Unsupported)),
                    Some(slot) => match slot.lock().expect("ota lock").take() {
                        Some(sink) => Ok(sink),
                        None => Err(self.refuse(Refusal::Busy)),
                    },
                };
                match taken {
                    Err(r) => r,
                    Ok(mut sink) => {
                        let outcome = match OtaSession::begin(manifest.clone(), sink.as_mut()) {
                            Err(r) => Err(r),
                            Ok(mut session) => {
                                // 3. ready: the bytes may come. A stream that
                                //    dies mid-way is a short image.
                                let ready = frame_of(&Response::OtaReady).ok().filter(|_| true);
                                let mut failed = None;
                                match ready {
                                    None => failed = Some(Refusal::LengthMismatch),
                                    Some(frame) => {
                                        if send.write_all(&frame).await.is_err() {
                                            failed = Some(Refusal::LengthMismatch);
                                        }
                                    }
                                }
                                let mut buf = vec![0u8; CHUNK_LEN];
                                while failed.is_none() && session.written() < manifest.image_len {
                                    match recv.read(&mut buf).await {
                                        Ok(Some(n)) => {
                                            if let Err(r) = session.push(&buf[..n]) {
                                                failed = Some(r);
                                            }
                                        }
                                        Ok(None) | Err(_) => failed = Some(Refusal::LengthMismatch),
                                    }
                                }
                                match failed {
                                    Some(r) => Err(r),
                                    None => session.finish(),
                                }
                            }
                        };
                        // the session is gone: the slot goes back either way
                        *self.0.ota.as_ref().expect("slot").lock().expect("ota lock") = Some(sink);
                        match outcome {
                            Ok(sha256) => {
                                self.0
                                    .counters
                                    .ota_committed
                                    .fetch_add(1, Ordering::Relaxed);
                                *self.0.last_ota.lock().expect("last ota") =
                                    Some(manifest.firmware.clone());
                                Response::OtaResult {
                                    firmware: manifest.firmware,
                                    sha256,
                                }
                            }
                            Err(r) => self.refuse(r),
                        }
                    }
                }
            }
        };
        let frame = frame_of(&response)?;
        send.write_all(&frame)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

#[derive(Clone)]
struct Sidecar(Arc<DeviceState>);

impl core::fmt::Debug for Sidecar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sidecar")
    }
}

impl ProtocolHandler for Sidecar {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request = recv
            .read_to_end(alpn::MAX_SIDECAR_BYTES)
            .await
            .map_err(AcceptError::from_err)?;
        let ticket = self.0.ticket_text.lock().expect("ticket lock").clone();
        let uuid = sidecar::device_uuid(&self.0.did);
        let node_id = self.0.identity.endpoint_id().to_string();
        let info = self.0.sidecar_info(&node_id, &[], &uuid);
        let neighbours = self
            .0
            .neighbours
            .as_ref()
            .map(|n| n.neighbours())
            .unwrap_or_default();
        let reply = sidecar::handle(
            &request,
            &info,
            Some((&self.0.manifest, &self.0.manifest_sig)),
            Some(&ticket),
            &neighbours,
        );
        self.0.counters.sidecar.fetch_add(1, Ordering::Relaxed);
        send.write_all(&reply)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

struct Media {
    state: Arc<DeviceState>,
    factory: Option<MediaFactory>,
}

impl core::fmt::Debug for Media {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Media")
    }
}

impl ProtocolHandler for Media {
    async fn accept(&self, connection: Connection) -> core::result::Result<(), AcceptError> {
        let Some(factory) = &self.factory else {
            return Err(AcceptError::from_err(HostError::Rpc(RpcError::Unsupported)));
        };
        let (mut send, mut recv) = connection.accept_bi().await?;
        let mut prefix = [0u8; 4];
        recv.read_exact(&mut prefix)
            .await
            .map_err(AcceptError::from_err)?;
        let n = rpc::frame_len(&prefix).map_err(AcceptError::from_err)?;
        let mut body = vec![0u8; n];
        recv.read_exact(&mut body)
            .await
            .map_err(AcceptError::from_err)?;
        let sub: Subscribe = rpc::decode_body(&body).map_err(AcceptError::from_err)?;
        // Acknowledge with the same frame; the subscriber knows packets follow.
        let ack = rpc::encode_frame(&sub).map_err(AcceptError::from_err)?;
        send.write_all(&ack).await.map_err(AcceptError::from_err)?;
        send.finish()?;
        self.state
            .counters
            .media_subscribers
            .fetch_add(1, Ordering::Relaxed);

        let mut source = factory(&sub);
        let interval = source.interval();
        // The source may block (a camera, an HTTP pull, a paced file): it
        // gets a thread of its own and a short channel, so one slow
        // subscriber's source never holds the executor — and with it every
        // other subscriber — hostage. Dropping the receiver ends the thread
        // after its next packet.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PacketHeader, Vec<u8>)>(4);
        tokio::task::spawn_blocking(move || {
            while let Some(pkt) = source.next_packet() {
                if tx.blocking_send(pkt).is_err() {
                    break;
                }
                if !interval.is_zero() {
                    std::thread::sleep(interval);
                }
            }
        });
        let closed = connection.closed();
        tokio::pin!(closed);
        let mut buf = Vec::new();
        loop {
            let (header, payload) = tokio::select! {
                _ = &mut closed => break,
                next = rx.recv() => match next {
                    Some(pkt) => pkt,
                    None => break,
                },
            };
            buf.clear();
            buf.resize(HEADER_LEN, 0);
            header
                .encode(&mut buf[..HEADER_LEN])
                .map_err(AcceptError::from_err)?;
            buf.extend_from_slice(&payload);
            let sent = if buf.len() <= alpn::MAX_MEDIA_DATAGRAM {
                connection
                    .send_datagram(Bytes::copy_from_slice(&buf))
                    .is_ok()
            } else {
                match connection.open_uni().await {
                    Ok(mut uni) => uni.write_all(&buf).await.is_ok() && uni.finish().is_ok(),
                    Err(_) => false,
                }
            };
            if sent {
                self.state
                    .counters
                    .media_packets
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                self.state
                    .counters
                    .media_send_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(rx);
        Ok(())
    }
}
