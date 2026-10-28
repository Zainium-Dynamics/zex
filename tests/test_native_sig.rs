//! Real-data regression tests for native_sig.rs's signature verification.
//!
//! The fixtures here are real, unmodified packages downloaded from the
//! actual Alpine (dl-cdn.alpinelinux.org), Chimera (repo.chimera-linux.org)
//! and Void (repo-default.voidlinux.org) repositories — not synthesized —
//! so a passing test here proves the verifier works against genuine
//! upstream signatures, not just a self-consistent round-trip.

use zex::cmd::install::native_sig;

#[test]
fn verifies_real_alpine_musl_package() {
    let data = std::fs::read("tests/fixtures/alpine-musl-1.2.6-r2.apk").unwrap();
    native_sig::verify_apk_v2(&data).expect("real Alpine musl package must verify");
}

#[test]
fn verifies_real_alpine_busybox_package() {
    let data = std::fs::read("tests/fixtures/alpine-busybox-1.36.1-r31.apk").unwrap();
    native_sig::verify_apk_v2(&data).expect("real Alpine busybox package must verify");
}

#[test]
fn rejects_tampered_alpine_package() {
    // apk-tools only signs the control member (offset 722..1246 in this
    // fixture) — tamper a byte inside that exact range to prove the
    // verifier actually checks it, rather than e.g. always passing.
    let mut data = std::fs::read("tests/fixtures/alpine-musl-1.2.6-r2.apk").unwrap();
    data[800] ^= 0xFF;
    assert!(
        native_sig::verify_apk_v2(&data).is_err(),
        "tampered control member must fail verification"
    );
}

#[test]
fn verifies_real_chimera_package() {
    let data = std::fs::read("tests/fixtures/chimera-chimerautils-15.0.3-r0.apk").unwrap();
    native_sig::verify_adb_v3(&data).expect("real Chimera package must verify");
}

#[test]
fn rejects_tampered_chimera_package() {
    let mut data = std::fs::read("tests/fixtures/chimera-chimerautils-15.0.3-r0.apk").unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    assert!(
        native_sig::verify_adb_v3(&data).is_err(),
        "tampered adb package must fail verification"
    );
}

#[test]
fn verifies_real_void_package() {
    let pkg = std::fs::read("tests/fixtures/void-busybox-1.34.1_12.xbps").unwrap();
    let sig2 = std::fs::read("tests/fixtures/void-busybox-1.34.1_12.xbps.sig2").unwrap();

    let meta: plist::Dictionary = plist::from_file("tests/fixtures/void-index-meta.plist").unwrap();
    let pubkey_pem = match meta.get("public-key").unwrap() {
        plist::Value::Data(d) => d.clone(),
        _ => panic!("public-key is not a data value"),
    };

    native_sig::verify_xbps(&pkg, &sig2, &pubkey_pem).expect("real Void package must verify");
}

#[test]
fn rejects_tampered_void_package() {
    let mut pkg = std::fs::read("tests/fixtures/void-busybox-1.34.1_12.xbps").unwrap();
    let sig2 = std::fs::read("tests/fixtures/void-busybox-1.34.1_12.xbps.sig2").unwrap();
    let meta: plist::Dictionary = plist::from_file("tests/fixtures/void-index-meta.plist").unwrap();
    let pubkey_pem = match meta.get("public-key").unwrap() {
        plist::Value::Data(d) => d.clone(),
        _ => panic!("public-key is not a data value"),
    };

    pkg[1000] ^= 0xFF;
    assert!(
        native_sig::verify_xbps(&pkg, &sig2, &pubkey_pem).is_err(),
        "tampered xbps package must fail verification"
    );
}
