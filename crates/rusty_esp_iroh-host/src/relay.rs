//! The relay + discovery configuration for reach beyond the LAN (the PSRAM
//! tier on a chip, any host): n0's public relays and pkarr lookup, with the
//! two shims the minimal crypto provider needs.
//!
//! Both shims are vendored from n0's `iroh-esp32-examples`
//! (`std_dns_resolver.rs`, `insecure_verifier.rs`, MIT OR Apache-2.0,
//! © n0 computer), lightly edited:
//!
//! - [`StdDnsResolver`]: DNS through the platform's `getaddrinfo` instead of
//!   hickory, whose async parser needs ~111 KB of stack on the chip. A and
//!   AAAA only; TXT lookups fail, which pkarr-over-HTTPS does not need.
//! - [`skip_verify`]: a no-op relay **TLS certificate** verifier. The provider
//!   has no RSA, so it cannot check the relay's certificate chain; iroh
//!   authenticates peers with their ed25519 keys at the QUIC layer, so the
//!   relay leg only needs an encrypted channel, not a verified one. Replace
//!   with a shipped trust anchor when relays serve ed25519 chains.

use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;

use iroh::address_lookup::{PkarrPublisher, PkarrResolver};
use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use iroh::endpoint::Builder;
use iroh::tls::CaTlsConfig;
use iroh::{NetReportConfig, RelayMode};
use iroh_relay::tls::ServerCertVerifierBuilder;
use n0_error::e;
use n0_future::boxed::BoxFuture;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Apply the relay tier to a builder: n0's default relays, pkarr publish and
/// resolve through n0's DNS, the std DNS shim, the no-op relay certificate
/// verifier, and no HTTPS latency probes or captive-portal checks (both
/// would make real-certificate TLS connections the provider cannot verify;
/// UDP QAD probes still measure relay latency).
#[must_use]
pub fn apply(builder: Builder) -> Builder {
    builder
        .relay_mode(RelayMode::Default)
        .dns_resolver(DnsResolver::custom(StdDnsResolver))
        .ca_tls_config(CaTlsConfig::custom_server_cert_verifier(skip_verify()))
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(PkarrResolver::n0_dns())
        // `NetReportConfig` is `#[non_exhaustive]`; `minimal()` is exactly
        // "no HTTPS probes, no captive-portal check".
        .net_report_config(NetReportConfig::minimal())
}

/// DNS through `std::net::ToSocketAddrs` (getaddrinfo) on a blocking task.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdDnsResolver;

fn strip_fqdn_dot(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

async fn lookup(host: String) -> Result<Vec<std::net::SocketAddr>, DnsError> {
    let h = strip_fqdn_dot(&host).to_string();
    let addrs = tokio::task::spawn_blocking(move || format!("{h}:0").to_socket_addrs())
        .await
        .map_err(|err| {
            log::warn!("std-dns {host}: blocking task failed: {err}");
            e!(DnsError::NoResponse)
        })?
        .map_err(|err| {
            log::debug!("std-dns {host}: getaddrinfo failed: {err}");
            e!(DnsError::NoResponse)
        })?;
    Ok(addrs.collect())
}

impl Resolver for StdDnsResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            let v4: Vec<Ipv4Addr> = lookup(host)
                .await?
                .into_iter()
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect();
            if v4.is_empty() {
                Err(e!(DnsError::NoResponse))
            } else {
                Ok(Box::new(v4.into_iter()) as BoxIter<Ipv4Addr>)
            }
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            let v6: Vec<Ipv6Addr> = lookup(host)
                .await?
                .into_iter()
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V6(ip) => Some(ip),
                    std::net::IpAddr::V4(_) => None,
                })
                .collect();
            if v6.is_empty() {
                Err(e!(DnsError::NoResponse))
            } else {
                Ok(Box::new(v6.into_iter()) as BoxIter<Ipv6Addr>)
            }
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        // getaddrinfo has no TXT; iroh's DNS endpoint discovery is not used
        // here (pkarr over HTTPS and direct connections are).
        Box::pin(async move {
            log::debug!("std-dns {host}: TXT not supported");
            Err(e!(DnsError::NoResponse))
        })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(*self)
    }
}

/// The callback `CaTlsConfig::custom_server_cert_verifier` takes, installing
/// a verifier that accepts any relay certificate (see the module docs).
#[must_use]
pub fn skip_verify() -> ServerCertVerifierBuilder {
    Arc::new(|crypto_provider| {
        Ok(Arc::new(NoCertVerifier { crypto_provider }) as Arc<dyn ServerCertVerifier>)
    })
}

#[derive(Debug)]
struct NoCertVerifier {
    crypto_provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
