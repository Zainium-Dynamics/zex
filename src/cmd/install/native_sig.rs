//! native_sig.rs: Real cryptographic signature verification for the

use anyhow::{Context, Result, bail};
use rsa::RsaPublicKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::io::Read;

#[derive(Clone, Copy)]
enum HashAlg {
    Sha1,
    Sha256,
    Sha512,
}

fn parse_pubkey(pem: &str) -> Result<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    RsaPublicKey::from_public_key_pem(pem)
        .context("failed to parse embedded trust-anchor public key")
}

fn verify_pkcs1v15(pubkey: &RsaPublicKey, alg: HashAlg, message: &[u8], sig: &[u8]) -> Result<()> {
    let result = match alg {
        HashAlg::Sha1 => {
            let digest = Sha1::digest(message);
            pubkey.verify(Pkcs1v15Sign::new::<Sha1>(), &digest, sig)
        }
        HashAlg::Sha256 => {
            let digest = Sha256::digest(message);
            pubkey.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
        }
        HashAlg::Sha512 => {
            let digest = Sha512::digest(message);
            pubkey.verify(Pkcs1v15Sign::new::<Sha512>(), &digest, sig)
        }
    };
    result.map_err(|e| anyhow::anyhow!("RSA signature verification failed: {e}"))
}

macro_rules! keyset {
    ($($file:literal),+ $(,)?) => {
        &[$(($file, include_str!(concat!("trust_keys/", $file)))),+]
    };
}

const ALPINE_KEYS: &[(&str, &str)] = keyset!(
    "alpine/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-58e4f17d.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-60ac2099.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-616a9724.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-616abc23.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-616ac3bc.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-616adfeb.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-616db30d.rsa.pub",
    "alpine/alpine-devel@lists.alpinelinux.org-66ba20fe.rsa.pub",
);

const CHIMERA_KEYS: &[(&str, &str)] = keyset!(
    "chimera/aarch64@chimera-linux.org-669d70e4.rsa.pub",
    "chimera/loongarch64@chimera-linux.org-67c2382b.rsa.pub",
    "chimera/ppc64@chimera-linux.org-669d70f6.rsa.pub",
    "chimera/ppc64le@chimera-linux.org-669d70f3.rsa.pub",
    "chimera/ppc@chimera-linux.org-6589fb18.rsa.pub",
    "chimera/q66@chimera-linux.org-61a1913b.rsa.pub",
    "chimera/riscv64@chimera-linux.org-669d70fa.rsa.pub",
    "chimera/x86_64@chimera-linux.org-669d70ff.rsa.pub",
);

fn gzip_member_boundaries(data: &[u8], max_members: usize) -> Result<Vec<usize>> {
    let mut offsets = vec![0usize];
    let mut pos = 0usize;
    for _ in 0..max_members {
        if pos >= data.len() {
            break;
        }
        let cursor = std::io::Cursor::new(&data[pos..]);
        let mut dec = flate2::bufread::GzDecoder::new(cursor);
        let mut discard = Vec::new();
        if dec.read_to_end(&mut discard).is_err() {
            break;
        }
        let consumed = dec.into_inner().position() as usize;
        if consumed == 0 {
            break;
        }
        pos += consumed;
        offsets.push(pos);
    }
    Ok(offsets)
}

/// Verifies an Alpine-format `.apk` file's embedded RSA signature.
///
/// Real apk v2 packages are 2-3 concatenated gzip streams: `[signature
/// tarball][control tarball][data tarball]`. Empirically confirmed against
/// live packages (not just read from source): the signature covers the
/// *compressed* bytes of the control member, not its decompressed tar
/// content: a real quirk of apk-tools' own signing implementation.  The
/// hash algorithm is encoded in the signature entry's filename inside the
/// first gzip member (`.SIGN.RSA/RSA256/RSA512.<keyname>`).
pub fn verify_apk_v2(data: &[u8]) -> Result<()> {
    let offsets = gzip_member_boundaries(data, 3)?;
    if offsets.len() < 3 {
        bail!("apk file has fewer than 2 gzip members — not a valid signed v2 package");
    }
    let sig_member = &data[offsets[0]..offsets[1]];
    let control_end = offsets.get(2).copied().unwrap_or(data.len());
    let control_compressed = &data[offsets[1]..control_end];

    let mut sig_tar_bytes = Vec::new();
    flate2::read::GzDecoder::new(sig_member)
        .read_to_end(&mut sig_tar_bytes)
        .context("failed to decompress apk signature tarball")?;

    let mut archive = tar::Archive::new(&sig_tar_bytes[..]);
    for entry in archive
        .entries()
        .context("failed to read apk signature tarball entries")?
    {
        let mut entry = entry.context("failed to read apk signature tarball entry")?;
        let path = entry
            .path()
            .context("bad path in signature tarball")?
            .to_string_lossy()
            .into_owned();
        let Some(rest) = path.strip_prefix(".SIGN.") else {
            continue;
        };

        let (alg, keyname) = if let Some(k) = rest.strip_prefix("RSA256.") {
            (HashAlg::Sha256, k)
        } else if let Some(k) = rest.strip_prefix("RSA512.") {
            (HashAlg::Sha512, k)
        } else if let Some(k) = rest.strip_prefix("RSA.") {
            (HashAlg::Sha1, k)
        } else {
            continue;
        };

        let Some((_, pem)) = ALPINE_KEYS
            .iter()
            .find(|(name, _)| name.rsplit('/').next() == Some(keyname))
        else {
            continue;
        };

        let mut sig_bytes = Vec::new();
        entry
            .read_to_end(&mut sig_bytes)
            .context("failed to read signature bytes")?;
        let pubkey = parse_pubkey(pem)?;
        verify_pkcs1v15(&pubkey, alg, control_compressed, &sig_bytes)
            .context("apk package signature did not verify against a trusted Alpine key")?;
        return Ok(());
    }

    bail!("apk package has no signature by a trusted Alpine key (unsigned or untrusted)")
}

fn chimera_key_id(pem: &str) -> Result<[u8; 16]> {
    let pubkey = parse_pubkey(pem)?;
    let der = pubkey
        .to_pkcs1_der()
        .context("failed to re-encode trust-anchor key as PKCS#1 DER")?;
    let digest = Sha512::digest(der.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}

/// Verifies a Chimera `.apk` (apk-tools v3 "ADB" format) package's
/// signature block.
///
/// Confirmed against a real `chimerautils` package fetched from
/// `repo.chimera-linux.org`: the digest covers the raw bytes of the
/// `ADB_BLOCK_ADB` (object graph) block using the algorithm named in the
/// signature block itself, then the *outer* signature is always
/// RSA-PKCS1v15-SHA512 over `LE32(schema) || sign_ver || hash_alg ||
/// key_id[16] || digest` (mirrors `adb_trust_verify_signature` in
/// apk-tools' `adb.c`). The 16-byte key id is the first 16 bytes of
/// SHA-512 over the trust anchor's PKCS#1 DER encoding: matching
/// `apk_pkey_init`'s `i2d_PublicKey` + SHA-512 in `crypto_openssl.c`.
pub fn verify_adb_v3(data: &[u8]) -> Result<()> {
    let decoded = super::adb::decode_envelope(data)?;
    if decoded.len() < 8 {
        bail!("adb: truncated file header");
    }
    let magic = u32::from_le_bytes(decoded[0..4].try_into().unwrap());
    if magic != 0x2e424441 {
        bail!("adb: bad file header magic");
    }
    let schema = u32::from_le_bytes(decoded[4..8].try_into().unwrap());

    let mut adb_block: Option<Vec<u8>> = None;
    let mut sig_blocks: Vec<Vec<u8>> = Vec::new();
    for blk in super::adb::iter_blocks(&decoded[8..])? {
        match blk.block_type {
            0 => adb_block = Some(blk.payload.to_vec()),
            1 => sig_blocks.push(blk.payload.to_vec()),
            _ => {}
        }
    }
    let adb_block = adb_block.ok_or_else(|| anyhow::anyhow!("adb: missing object-graph block"))?;
    if sig_blocks.is_empty() {
        bail!("adb package has no signature block (unsigned)");
    }

    for sig_block in &sig_blocks {
        if sig_block.len() < 18 {
            continue;
        }
        let sign_ver = sig_block[0];
        let hash_alg = sig_block[1];
        if sign_ver != 0 {
            continue;
        }
        let key_id = &sig_block[2..18];
        let sig_bytes = &sig_block[18..];

        let md = match hash_alg {
            3 => Sha256::digest(&adb_block).to_vec(),
            4 => Sha512::digest(&adb_block).to_vec(),
            _ => continue,
        };

        let mut msg = Vec::with_capacity(4 + 2 + 16 + md.len());
        msg.extend_from_slice(&schema.to_le_bytes());
        msg.push(sign_ver);
        msg.push(hash_alg);
        msg.extend_from_slice(key_id);
        msg.extend_from_slice(&md);

        for (_, pem) in CHIMERA_KEYS {
            let Ok(id) = chimera_key_id(pem) else {
                continue;
            };
            if id != key_id {
                continue;
            }
            let pubkey = parse_pubkey(pem)?;
            if verify_pkcs1v15(&pubkey, HashAlg::Sha512, &msg, sig_bytes).is_ok() {
                return Ok(());
            }
        }
    }

    bail!("adb package signature did not verify against a trusted Chimera key")
}

const VOID_TRUST_DIR: &str = "/overlayer/zexlib/registry/trust/void";

/// Trust-on-first-use pin for a Void repo's signing key.
///
/// This matches xbps' own trust model exactly: the repodata itself
/// self-declares its signing key (`index-meta.plist`'s `public-key` /
/// `signature-by` fields: confirmed against a live
/// `repo-default.voidlinux.org` repodata fetch), and real xbps pins it
/// locally the first time a repo is seen, then requires an exact match on
/// every subsequent fetch. It can't authenticate the very first contact
/// (no independent out-of-band root of trust exists for this), but it does
/// catch key rotation or a MITM/compromised-mirror substitution on every
/// later run.
pub fn tofu_pin_void_key(mirror_id: &str, pem: &[u8], signed_by: &str) -> Result<Vec<u8>> {
    let dir = std::path::Path::new(VOID_TRUST_DIR);
    std::fs::create_dir_all(dir).context("failed to create Void trust store directory")?;
    let path = dir.join(format!("{mirror_id}.pem"));

    if path.exists() {
        let pinned = std::fs::read(&path).context("failed to read pinned Void trust key")?;
        if pinned != pem {
            bail!(
                "Void repo '{mirror_id}' signing key changed since it was first trusted \
                 (now signed-by: {signed_by}) — refusing to silently accept a new key. \
                 If this is an expected, legitimate key rotation, remove {} and retry.",
                path.display()
            );
        }
        Ok(pinned)
    } else {
        std::fs::write(&path, pem).context("failed to pin Void trust key")?;
        log::info!("Void repo '{mirror_id}' signing key pinned (signed-by: {signed_by})");
        Ok(pem.to_vec())
    }
}

/// Verifies a Void `.xbps` package against its detached `.sig2` signature
/// and a (TOFU-pinned) repo public key.
///
/// Confirmed against a real `busybox` package + `.sig2` fetched from
/// `repo-default.voidlinux.org`: this is plain RSA-PKCS1v15-SHA256 over
/// the SHA-256 digest of the *entire* `.xbps` file: matching
/// `RSA_verify(NID_sha256, ...)` in xbps' own `verifysig.c` exactly.
pub fn verify_xbps(pkg_bytes: &[u8], sig2_bytes: &[u8], pinned_pubkey_pem: &[u8]) -> Result<()> {
    let pem =
        std::str::from_utf8(pinned_pubkey_pem).context("pinned Void key is not valid UTF-8")?;
    let pubkey = parse_pubkey(pem)?;
    verify_pkcs1v15(&pubkey, HashAlg::Sha256, pkg_bytes, sig2_bytes)
        .context("xbps package signature did not verify against the pinned repo key")
}
