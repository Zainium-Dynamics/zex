//! vercmp.rs — version comparison for update driver.
//!
//! Same pure structural rules as `cmd::upgrade::vercmp`:
//! numeric parts first, then raw suffix lexicographic.
//! No hardcoded prerelease keyword lists.

use std::cmp::Ordering;

pub fn is_upgrade(local: &str, remote: &str) -> bool {
    cmp_ver(remote, local) == Ordering::Greater
}

fn cmp_ver(a: &str, b: &str) -> Ordering {
    let (a_num, a_suf) = split_suffix(a);
    let (b_num, b_suf) = split_suffix(b);
    let a_parts: Vec<u64> = a_num.split('.').filter_map(|p| p.parse().ok()).collect();
    let b_parts: Vec<u64> = b_num.split('.').filter_map(|p| p.parse().ok()).collect();
    let max = a_parts.len().max(b_parts.len());
    for i in 0..max {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }
    a_suf.cmp(b_suf)
}

fn split_suffix(s: &str) -> (&str, &str) {
    let i = s.bytes().take_while(|b| b.is_ascii_digit() || *b == b'.').count();
    (&s[..i], &s[i..])
}
