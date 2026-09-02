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

    fn dispatch(&self, env: Envelope) -> Response {
        let now = now_unix();
        let caller = {
            let mut window = self.window.lock().expect("window lock");
            rpc::authorize(&env, &self.did, self.pin().as_ref(), now, &mut window)
        };
        let caller = match caller {
            Ok(c) => c,
            Err(e) => {
                self.counters.rpc_refused.fetch_add(1, Ordering::Relaxed);
                return Response::Error(e);
            }
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
            counters: Counters::default(),
        });

        let router = Router::builder(endpoint.clone())
            .accept(alpn::ECHO, Echo(state.clone()))
            .accept(alpn::RPC, Rpc(state.clone()))
            .accept(alpn::SIDECAR_RPC, Sidecar(state.clone()))
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
        let reply = sidecar::handle(
            &request,
            &info,
            Some((&self.0.manifest, &self.0.manifest_sig)),
            Some(&ticket),
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
        let closed = connection.closed();
        tokio::pin!(closed);
        let mut buf = Vec::new();
        while let Some((header, payload)) = source.next_packet() {
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
            tokio::select! {
                _ = &mut closed => break,
                () = tokio::time::sleep(interval) => {}
            }
        }
        Ok(())
    }
}
