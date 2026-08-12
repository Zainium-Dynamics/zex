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


/// SPKI SHA-256 pins (base64) for hosts that require certificate pinning.
///
/// `archive.zainiumdynamics.tech` moved from an Oracle-hosted origin to
/// Cloudflare (fronting R2 storage) — this pin was stale against the old
/// Oracle cert until refreshed against the real live cert on 2026-08-12
/// (`echo | openssl s_client -connect archive.zainiumdynamics.tech:443
/// -servername archive.zainiumdynamics.tech | openssl x509 -pubkey -noout
/// | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary |
/// base64`). Every stale pin here fails *silently* wherever the caller
/// doesn't explicitly surface the TLS error (e.g. `cmd::update::main`'s
/// `.unwrap_or_default()` on the diff calls turned "every HTTPS request
/// rejected" into a plain "no updates available") — if `zex` starts
/// reporting suspiciously-empty results against this host again, check
/// this pin against the live cert before assuming there's nothing to do.
/// `PINS_CONFIG_PATH` below can override this without a rebuild if the
/// cert rotates again (Cloudflare-fronted origins can rotate more often
/// than a single hardcoded leaf-cert pin comfortably tolerates).
const DEFAULT_PINS: &[(&str, &[&str])] = &[(
    "archive.zainiumdynamics.tech",
    &["j3xLhYimysNA/zKow20gJ0g0LsiNcHhflTSjuSBoe+Q="],
)];

const PINS_CONFIG_PATH: &str = "/overlayer/syshub/engine/services/tls_pins.toml";

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

    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(4 * 60 * 60))
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .user_agent(user_agent)
        .use_preconfigured_tls(tls)
        .build()
        .context("building HTTP client")
}

fn load_pins() -> HashMap<String, Vec<Vec<u8>>> {
    let mut pins: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    for (host, b64_list) in DEFAULT_PINS {
        let decoded: Vec<Vec<u8>> = b64_list
            .iter()
            .filter_map(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .collect();
        if !decoded.is_empty() {
            pins.insert((*host).to_string(), decoded);
        }
    }

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
    fn default_pins_load_for_archive_host() {
        let pins = load_pins();
        assert!(pins.contains_key("archive.zainiumdynamics.tech"));
        assert!(!pins["archive.zainiumdynamics.tech"].is_empty());
    }

    #[test]
    fn builds_http_client() {
        build("zex-test/5.0.0").unwrap();
    }
}