//! Pollard's kangaroo for a known public key in a bounded range [start, start + 2^(bits-1)).
//! Many kangaroos per thread share one field inversion per step (Montgomery's trick).
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::Rng;
use rayon::prelude::*;
use scan_core::fe::{self, Fe};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

const JUMPS: usize = 64;
const HERD: usize = 256; // per kind, per thread

fn xy(p: &AffinePoint) -> (Fe, Fe) {
    let e = p.to_encoded_point(false);
    let b = e.as_bytes();
    (fe::from_be(&b[1..33]), fe::from_be(&b[33..65]))
}

fn mul_g(k: u128) -> AffinePoint {
    (ProjectivePoint::GENERATOR * Scalar::from(k)).to_affine()
}

pub struct Outcome {
    pub key: Option<u128>,
    pub ops: u64,
}

/// Find k in [start, start + 2^(bits-1)) with k·G == q. `bits` ≤ 126.
pub fn solve(q: &AffinePoint, start: u128, bits: u32, jump_scale: f64, max_ops: u64) -> Outcome {
    assert!((2..=126).contains(&bits));
    let w: u128 = 1u128 << (bits - 1);
    let mid = start + w / 2;
    let sqrt_w = (w as f64).sqrt();
    // Jump distances: uniform in [1, 2*mean]; mean ≈ jump_scale * sqrt(W).
    let mean = (sqrt_w * jump_scale).max(1.0) as u128;
    let mut rng = rand::thread_rng();
    let dist: Vec<u128> = (0..JUMPS).map(|_| rng.gen_range(1..=2 * mean)).collect();
    let jp: Vec<(Fe, Fe)> = dist.iter().map(|&d| xy(&mul_g(d))).collect();
    // DP when the low `dbits` bits of x are zero; keeps the table to ~tens of thousands of entries.
    let dbits = ((sqrt_w.log2() as i32) - 12).clamp(0, 40) as u32;
    let dmask: u64 = if dbits == 0 { 0 } else { (1u64 << dbits) - 1 };
    let spread = (sqrt_w as u128).max(1);

    let table: Mutex<HashMap<u128, (u128, bool)>> = Mutex::new(HashMap::new());
    let found = AtomicBool::new(false);
    let result = Mutex::new(None::<u128>);
    let ops = AtomicU64::new(0);
    let qx = *q;
    let threads = rayon::current_num_threads();

    (0..threads).into_par_iter().for_each(|_| {
        let mut rng = rand::thread_rng();
        let n = 2 * HERD;
        let (mut px, mut py) = (vec![fe::ZERO; n], vec![fe::ZERO; n]);
        let mut off = vec![0u128; n]; // r + travelled distance
        let tame = |i: usize| i < HERD;
        let mid_pt = ProjectivePoint::from(mul_g(mid));
        let q_pt = ProjectivePoint::from(qx);
        for i in 0..n {
            let r = rng.gen_range(0..spread);
            let base = if tame(i) { mid_pt } else { q_pt };
            let p = (base + ProjectivePoint::GENERATOR * Scalar::from(r)).to_affine();
            let (x, y) = xy(&p);
            px[i] = x;
            py[i] = y;
            off[i] = r;
        }
        let mut dx = vec![fe::ZERO; n];
        let mut scratch: Vec<Fe> = Vec::with_capacity(n);
        let mut idx = vec![0usize; n];
        let mut local = 0u64;
        while !found.load(Ordering::Relaxed) {
            for i in 0..n {
                idx[i] = (px[i][0] as usize) & (JUMPS - 1);
                let d = fe::sub(&jp[idx[i]].0, &px[i]);
                dx[i] = if fe::normalize(&d) == fe::ZERO { fe::ONE } else { d };
            }
            fe::batch_inv(&mut dx, &mut scratch);
            for i in 0..n {
                let (jx, jy) = &jp[idx[i]];
                let lam = fe::mul(&fe::sub(jy, &py[i]), &dx[i]);
                let x3 = fe::sub(&fe::sub(&fe::sqr(&lam), &px[i]), jx);
                let y3 = fe::sub(&fe::mul(&lam, &fe::sub(&px[i], &x3)), &py[i]);
                px[i] = x3;
                py[i] = y3;
                off[i] += dist[idx[i]];
                if px[i][0] & dmask == 0 {
                    let xn = fe::normalize(&px[i]);
                    let key = (xn[0] as u128) | ((xn[1] as u128) << 64);
                    let mut t = table.lock().unwrap();
                    match t.get(&key).copied() {
                        Some((o2, was_tame)) if was_tame != tame(i) => {
                            let (ot, ow) = if tame(i) { (off[i], o2) } else { (o2, off[i]) };
                            let k = (mid + ot).wrapping_sub(ow);
                            if mul_g(k) == qx {
                                *result.lock().unwrap() = Some(k);
                                found.store(true, Ordering::Relaxed);
                            }
                        }
                        _ => {
                            t.insert(key, (off[i], tame(i)));
                        }
                    }
                }
            }
            local += n as u64;
            if local >= 4096 {
                if ops.fetch_add(local, Ordering::Relaxed) + local >= max_ops {
                    found.store(true, Ordering::Relaxed);
                }
                local = 0;
            }
        }
        ops.fetch_add(local, Ordering::Relaxed);
    });
    let key = *result.lock().unwrap();
    Outcome { key, ops: ops.load(Ordering::Relaxed) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_random_keys_in_several_ranges() {
        for bits in [24u32, 30, 34] {
            for _ in 0..3 {
                let start = 1u128 << (bits - 1);
                let k = start + rand::thread_rng().gen_range(0..start);
                let q = mul_g(k);
                let o = solve(&q, start, bits, 256.0, 1 << 34);
                assert_eq!(o.key, Some(k), "bits {bits}");
            }
        }
    }

    #[test]
    fn gives_up_at_the_op_cap_without_a_wrong_answer() {
        let bits = 40u32;
        let start = 1u128 << (bits - 1);
        let q = mul_g(start + 12345);
        let o = solve(&q, start, bits, 256.0, 4096);
        assert!(o.key.is_none() || o.key == Some(start + 12345));
    }
}
