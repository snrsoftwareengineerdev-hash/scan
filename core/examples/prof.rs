use k256::elliptic_curve::group::Curve;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint};
use scan_core::addr::*;
use std::time::Instant;
fn main() {
    let n = 1_000_000usize;
    let g = ProjectivePoint::GENERATOR;
    let mut cur = g;
    let mut buf = vec![ProjectivePoint::IDENTITY; 1024];
    let mut aff = vec![AffinePoint::IDENTITY; 1024];
    let (mut t_add, mut t_norm, mut t_enc, mut t_hash) = (0f64, 0f64, 0f64, 0f64);
    let mut sink = 0u8;
    for _ in 0..n / 1024 {
        let t = Instant::now();
        for s in buf.iter_mut() { *s = cur; cur += g; }
        t_add += t.elapsed().as_secs_f64();
        let t = Instant::now();
        <ProjectivePoint as Curve>::batch_normalize(&buf, &mut aff);
        t_norm += t.elapsed().as_secs_f64();
        let t = Instant::now();
        let encs: Vec<_> = aff.iter().map(|a| a.to_encoded_point(true)).collect();
        t_enc += t.elapsed().as_secs_f64();
        let t = Instant::now();
        for e in &encs { sink ^= hash160(e.as_bytes())[0]; }
        t_hash += t.elapsed().as_secs_f64();
    }
    let k = (n / 1024 * 1024) as f64;
    println!("per key ns: add {:.0}  normalize {:.0}  encode {:.0}  hash160 {:.0} (sink {sink})", t_add/k*1e9, t_norm/k*1e9, t_enc/k*1e9, t_hash/k*1e9);
}
