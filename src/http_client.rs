//! Shared HTTP client with TLS SPKI pinning for Zainium primary mirrors.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use rustls::{Error, RootCertStore, SignatureScheme};


/// Optional SPKI SHA-256 pins (base64) per host, `[host]` table in this file.
/// No pins are built in: Cloudflare rotates the archive's leaf cert, and a
/// stale pin rejected every request to it. Without the file, hosts get plain
/// WebPKI verification; `zex refresh` shows any pin mismatch per mirror.
const PINS_CONFIG_PATH: &str = "/overlayer/syshub/engine/services/tls_pins.toml";

/// zex is static, so musl's resolver only reads /etc/resolv.conf, which Zainium doesn't have.
const RESOLV_CONF_PATH: &str = "/overlayer/syshub/etc/resolv.conf";

#[derive(Debug, serde::Deserialize, Default)]
struct PinsFile {
    #[serde(default)]
    host: HashMap<String, Vec<String>>,
}

/// Build the shared `reqwest::Client` used by install, update, search, and upgrade.
///
/// The same client this crate builds for lightweight metadata calls (ping,
/// HEAD, manifest/ledger fetches) is also the one every download path
/// reuses for the actual package bytes (`cmd::upgrade::userland`,
/// `cmd::update::apply` both take a shared client rather than building a
/// download-specific one) — so `.timeout()` here is a ceiling on the
/// *entire* request, including the full body transfer, not just a connect
/// timeout. 300s was sized for API-style calls and silently turned any
/// large package (gcc/rust-toolchain scale, 100MB-2GB+) on a real-world
/// (non-datacenter-to-datacenter) connection into a guaranteed failure —
/// confirmed live against archive.zainiumdynamics.tech, where a 113MB
/// package alone didn't finish in 300s. 4 hours comfortably covers a 2GB
/// package even on a slow link; this is always a manually-invoked,
/// supervised CLI command, so a generous ceiling costs nothing in the
/// normal case and a truly-hung connection is still bounded, just later.
pub fn build(user_agent: &str) -> Result<reqwest::Client> {
    let pins = load_pins();
    let tls = build_rustls_config(&pins)?;

    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(4 * 60 * 60))
        // a stalled transfer (no bytes for 30s) errors out so the downloader retries
        .read_timeout(std::time::Duration::from_secs(30))
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .user_agent(user_agent)
        .use_preconfigured_tls(tls);
    if let Some(resolver) = ZainiumResolver::from_resolv_conf() {
        builder = builder.dns_resolver(Arc::new(resolver));
    }
    builder.build().context("building HTTP client")
}

/// DNS from Zainium's resolv.conf, IPv4 first.
struct ZainiumResolver(hickory_resolver::TokioAsyncResolver);

impl ZainiumResolver {
    fn from_resolv_conf() -> Option<Self> {
        let raw = std::fs::read(RESOLV_CONF_PATH).ok()?;
        let (config, mut opts) = hickory_resolver::system_conf::parse_resolv_conf(raw)
            .map_err(|e| log::warn!("{RESOLV_CONF_PATH}: {e}"))
            .ok()?;
        opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;
        Some(Self(hickory_resolver::TokioAsyncResolver::tokio(config, opts)))
    }
}

impl reqwest::dns::Resolve for ZainiumResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = self.0.clone();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: reqwest::dns::Addrs =
                Box::new(lookup.into_iter().map(|ip| std::net::SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

fn load_pins() -> HashMap<String, Vec<Vec<u8>>> {
    let mut pins: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    if let Ok(raw) = std::fs::read_to_string(PINS_CONFIG_PATH) {
        if let Ok(file) = toml::from_str::<PinsFile>(&raw) {
            for (host, b64_list) in file.host {
                let decoded: Vec<Vec<u8>> = b64_list
                    .iter()
                    .filter_map(|b64| {
                        base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()
                    })
                    .collect();
                if !decoded.is_empty() {
                    pins.insert(host, decoded);
                }
            }
        }
    }

    pins
}

fn build_rustls_config(pins: &HashMap<String, Vec<Vec<u8>>>) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let inner = WebPkiServerVerifier::builder(roots.into())
        .build()
        .map_err(|e| anyhow::anyhow!("webpki verifier: {e}"))?;

    let verifier = Arc::new(SpkiPinVerifier {
        inner,
        pins: pins.clone(),
    });

    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[derive(Debug)]
struct SpkiPinVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: HashMap<String, Vec<Vec<u8>>>,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        if let ServerName::DnsName(dns) = server_name {
            let host = dns.as_ref();
            if let Some(expected) = self.pins.get(host) {
                let spki = spki_hash(end_entity)?;
                if !expected.iter().any(|pin| pin == &spki) {
                    return Err(Error::General(format!(
                        "TLS SPKI pin mismatch for {host}"
                    )));
                }
                log::debug!("TLS SPKI pin verified for {host}");
            }
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn spki_hash(cert: &CertificateDer<'_>) -> Result<Vec<u8>, Error> {
    use sha2::{Digest, Sha256};
    let ee = webpki::EndEntityCert::try_from(cert)
        .map_err(|e| Error::General(format!("x509 parse failed: {e}")))?;
    Ok(Sha256::digest(ee.subject_public_key_info().as_ref()).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_http_client() {
        build("zex-test/5.0.0").unwrap();
    }
}