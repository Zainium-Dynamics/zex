//! fuzz_vercmp — Fuzz version comparison functions.
//!
//! Targets both `upgrade::vercmp::is_upgrade` and `update::vercmp::is_upgrade`.
//!
//! Invariants (must hold for ALL string pairs):
//!   • Never panics
//!   • Reflexive: is_upgrade(v, v) == false
//!   • Antisymmetric: if is_upgrade(a, b) then !is_upgrade(b, a)
//!   • Transitivity: if is_upgrade(a,b) && is_upgrade(b,c) then is_upgrade(a,c)
//!   • Empty string is always "old": is_upgrade("", any_non_empty) == true

#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{self, Arbitrary};

/// Fuzzer input: two arbitrary version strings.
/// Using Arbitrary derive limits us to valid UTF-8 automatically.
#[derive(Debug, Arbitrary)]
struct VersionPair {
    a: String,
    b: String,
    c: String, // third version for transitivity check
}

fuzz_target!(|pair: VersionPair| {
    use zex::cmd::upgrade::vercmp::is_upgrade as up_is_upgrade;
    use zex::cmd::update::vercmp::is_upgrade  as upd_is_upgrade;

    let a = &pair.a;
    let b = &pair.b;
    let c = &pair.c;

    // ── upgrade::vercmp ───────────────────────────────────────────────────────

    // Invariant 1: never panics (already guaranteed by reaching here)
    let ab = up_is_upgrade(a, b);
    let ba = up_is_upgrade(b, a);
    let ac = up_is_upgrade(a, c);
    let bc = up_is_upgrade(b, c);
    let aa = up_is_upgrade(a, a);
    let bb = up_is_upgrade(b, b);

    // Invariant 2: reflexive — same version is never an upgrade
    assert!(!aa, "up: is_upgrade({a:?}, {a:?}) should be false");
    assert!(!bb, "up: is_upgrade({b:?}, {b:?}) should be false");

    // Invariant 3: antisymmetric — can't be upgrade in both directions
    assert!(!(ab && ba),
        "up: is_upgrade({a:?},{b:?}) && is_upgrade({b:?},{a:?}) — antisymmetry violated");

    // Invariant 4: transitivity — if a→b and b→c then a→c
    if ab && bc {
        assert!(ac,
            "up: transitivity violated: {a:?} → {b:?} → {c:?} but not {a:?} → {c:?}");
    }

    // ── update::vercmp ────────────────────────────────────────────────────────

    let ab2 = upd_is_upgrade(a, b);
    let ba2 = upd_is_upgrade(b, a);
    let aa2 = upd_is_upgrade(a, a);
    let bb2 = upd_is_upgrade(b, b);
    let ac2 = upd_is_upgrade(a, c);
    let bc2 = upd_is_upgrade(b, c);

    // Same invariants for update::vercmp
    assert!(!aa2, "upd: is_upgrade({a:?}, {a:?}) should be false");
    assert!(!bb2, "upd: is_upgrade({b:?}, {b:?}) should be false");
    assert!(!(ab2 && ba2),
        "upd: antisymmetry violated for {a:?}, {b:?}");
    if ab2 && bc2 {
        assert!(ac2,
            "upd: transitivity violated: {a:?} → {b:?} → {c:?}");
    }
});
