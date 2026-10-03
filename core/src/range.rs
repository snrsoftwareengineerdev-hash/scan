use crate::addr::*;
use k256::elliptic_curve::group::Curve;
use k256::{AffinePoint, ProjectivePoint};
use std::sync::atomic::{AtomicBool, Ordering};

const BATCH: usize = 1024;

#[derive(Debug, Clone)]
pub struct Hit {
    pub key: [u8; 32],
    pub compressed: bool,
}

/// Test `count` consecutive keys from `start` against `target` (hash160).
/// `stop` cancels sibling chunks. Returns (hit, keys_tested).
pub fn scan_range(
    start: &[u8; 32],
    count: u64,
    target: &[u8; 20],
    try_uncompressed: bool,
    stop: &AtomicBool,
) -> Result<(Option<Hit>, u64), AddrError> {
    let g = ProjectivePoint::GENERATOR;
    let mut cur = g * scalar_from_be(start)?;
    let mut done = 0u64;
    let mut buf = vec![ProjectivePoint::IDENTITY; BATCH];
    let mut aff = vec![AffinePoint::IDENTITY; BATCH];

    while done < count {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let n = ((count - done) as usize).min(BATCH);
        for slot in buf.iter_mut().take(n) {
            *slot = cur;
            cur += g;
        }
        <ProjectivePoint as Curve>::batch_normalize(&buf[..n], &mut aff[..n]);
        for (i, a) in aff[..n].iter().enumerate() {
            let c = p2pkh_hash160(a, true) == *target;
            if c || (try_uncompressed && p2pkh_hash160(a, false) == *target) {
                let key = add_be(start, (done + i as u64) as u128);
                return Ok((Some(Hit { key, compressed: c }), done + i as u64 + 1));
            }
        }
        done += n as u64;
    }
    Ok((None, done))
}
