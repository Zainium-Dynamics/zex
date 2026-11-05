//! fuzz_vercmp: Fuzz version comparison functions.

#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{self, Arbitrary};

/// Fuzzer input: two arbitrary version strings.
/// Using Arbitrary derive limits us to valid UTF-8 automatically.
#[derive(Debug, Arbitrary)]
struct VersionPair {
    a: String,
    b: String,
    c: String,
}

fuzz_target!(|pair: VersionPair| {
    use zex::cmd::upgrade::vercmp::is_upgrade as up_is_upgrade;
    use zex::cmd::update::vercmp::is_upgrade  as upd_is_upgrade;

    let a = &pair.a;
    let b = &pair.b;
    let c = &pair.c;

    let ab = up_is_upgrade(a, b);
    let ba = up_is_upgrade(b, a);
    let ac = up_is_upgrade(a, c);
    let bc = up_is_upgrade(b, c);
    let aa = up_is_upgrade(a, a);
    let bb = up_is_upgrade(b, b);

    assert!(!aa, "up: is_upgrade({a:?}, {a:?}) should be false");
    assert!(!bb, "up: is_upgrade({b:?}, {b:?}) should be false");

    assert!(!(ab && ba),
        "up: is_upgrade({a:?},{b:?}) && is_upgrade({b:?},{a:?}) — antisymmetry violated");

    if ab && bc {
        assert!(ac,
            "up: transitivity violated: {a:?} → {b:?} → {c:?} but not {a:?} → {c:?}");
    }

    let ab2 = upd_is_upgrade(a, b);
    let ba2 = upd_is_upgrade(b, a);
    let aa2 = upd_is_upgrade(a, a);
    let bb2 = upd_is_upgrade(b, b);
    let ac2 = upd_is_upgrade(a, c);
    let bc2 = upd_is_upgrade(b, c);

    assert!(!aa2, "upd: is_upgrade({a:?}, {a:?}) should be false");
    assert!(!bb2, "upd: is_upgrade({b:?}, {b:?}) should be false");
    assert!(!(ab2 && ba2),
        "upd: antisymmetry violated for {a:?}, {b:?}");
    if ab2 && bc2 {
        assert!(ac2,
            "upd: transitivity violated: {a:?} → {b:?} → {c:?}");
    }
});
