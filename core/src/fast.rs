//! Fast sequential range walk: centered batches P_c ± i·G with one shared inversion per batch.
use crate::addr::*;
use crate::fe::{self, Fe};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

pub const HALF: usize = 512;
pub const BATCH: usize = 2 * HALF + 1;

pub struct Tables {
    tx: Vec<Fe>, // x of i*G, i=1..=HALF
    ty: Vec<Fe>,
    step: (Fe, Fe), // BATCH*G
}

fn xy(p: &AffinePoint) -> (Fe, Fe) {
    let e = p.to_encoded_point(false);
    let b = e.as_bytes();
    (fe::from_be(&b[1..33]), fe::from_be(&b[33..65]))
}

fn mul_g(k: u64) -> AffinePoint {
    (ProjectivePoint::GENERATOR * Scalar::from(k)).to_affine()
}

impl Tables {
    pub fn new() -> Tables {
        let (mut tx, mut ty) = (Vec::with_capacity(HALF), Vec::with_capacity(HALF));
        for i in 1..=HALF as u64 {
            let (x, y) = xy(&mul_g(i));
            tx.push(x);
            ty.push(y);
        }
        Tables { tx, ty, step: xy(&mul_g(BATCH as u64)) }
    }
}

impl Default for Tables {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimum start key for the fast path (center ± HALF must never coincide with a table point).
pub const MIN_FAST_KEY: u128 = 4 * HALF as u128;

pub fn fast_ok(start: &[u8; 32]) -> bool {
    start[..16].iter().all(|&b| b == 0) && u128::from_be_bytes(start[16..].try_into().unwrap()) >= MIN_FAST_KEY
        || start[..16].iter().any(|&b| b != 0) && start[0] < 0x7f
}

#[inline(always)]
fn hash160_c(x: &Fe, y: &Fe, buf: &mut [u8; 33]) -> [u8; 20] {
    let ny = fe::normalize(y);
    buf[0] = 0x02 | (ny[0] & 1) as u8;
    buf[1..].copy_from_slice(&fe::to_be(x));
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(Sha256::digest(&buf[..])));
    out
}

/// Same contract as `range::scan_range` (compressed keys only), several times faster.
/// Requires `fast_ok(start)`.
pub fn scan_fast(t: &Tables, start: &[u8; 32], count: u64, target: &[u8; 20], stop: &AtomicBool) -> Result<(Option<[u8; 32]>, u64), AddrError> {
    let center_key = add_be(start, HALF as u128);
    let _ = scalar_from_be(&center_key)?;
    let s: Option<Scalar> = Scalar::from_repr(center_key.into()).into();
    let c0 = {
        (ProjectivePoint::GENERATOR * s.unwrap()).to_affine()
    };
    let (mut cx, mut cy) = xy(&c0);

    let mut dx = vec![fe::ZERO; HALF];
    let mut scratch: Vec<Fe> = Vec::with_capacity(HALF);
    let mut px = vec![fe::ZERO; BATCH];
    let mut py = vec![fe::ZERO; BATCH];
    let mut done = 0u64;
    let mut buf = [0u8; 33];

    while done < count {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        for i in 0..HALF {
            dx[i] = fe::sub(&t.tx[i], &cx);
        }
        fe::batch_inv(&mut dx, &mut scratch);
        for i in 0..HALF {
            let inv = &dx[i];
            // plus: C + (i+1)G  -> index HALF + i + 1
            let lam = fe::mul(&fe::sub(&t.ty[i], &cy), inv);
            let x3 = fe::sub(&fe::sub(&fe::sqr(&lam), &cx), &t.tx[i]);
            let y3 = fe::sub(&fe::mul(&lam, &fe::sub(&cx, &x3)), &cy);
            px[HALF + i + 1] = x3;
            py[HALF + i + 1] = y3;
            // minus: C - (i+1)G -> index HALF - i - 1, partner point has y negated
            let ny = fe::sub(&fe::ZERO, &t.ty[i]);
            let lam = fe::mul(&fe::sub(&ny, &cy), inv);
            let x3 = fe::sub(&fe::sub(&fe::sqr(&lam), &cx), &t.tx[i]);
            let y3 = fe::sub(&fe::mul(&lam, &fe::sub(&cx, &x3)), &cy);
            px[HALF - i - 1] = x3;
            py[HALF - i - 1] = y3;
        }
        px[HALF] = cx;
        py[HALF] = cy;

        let n = ((count - done) as usize).min(BATCH);
        if let Some(j) = find_match(&px[..n], &py[..n], target, &mut buf) {
            return Ok((Some(add_be(start, (done + j as u64) as u128)), done + j as u64 + 1));
        }
        done += n as u64;
        if done >= count {
            break;
        }
        // advance center by BATCH keys: C += step (one inversion)
        let (sx, sy) = t.step;
        let inv = fe::inv(&fe::sub(&sx, &cx));
        let lam = fe::mul(&fe::sub(&sy, &cy), &inv);
        let x3 = fe::sub(&fe::sub(&fe::sqr(&lam), &cx), &sx);
        let y3 = fe::sub(&fe::mul(&lam, &fe::sub(&cx, &x3)), &cy);
        cx = x3;
        cy = y3;
    }
    Ok((None, done))
}

/// First index in the batch whose compressed-key hash160 equals `target` (AVX2 8-lane path when available).
fn find_match(px: &[Fe], py: &[Fe], target: &[u8; 20], buf: &mut [u8; 33]) -> Option<usize> {
    let n = px.len();
    let mut j = 0;
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        use core::arch::x86_64::*;
        let t0 = u32::from_le_bytes(target[..4].try_into().unwrap());
        while j + 8 <= n {
            let mut words = [[0u32; 8]; 8];
            for l in 0..8 {
                let ny = fe::normalize(&py[j + l]);
                buf[0] = 0x02 | (ny[0] & 1) as u8;
                buf[1..].copy_from_slice(&fe::to_be(&px[j + l]));
                let d = Sha256::digest(&buf[..]);
                for (w, row) in words.iter_mut().enumerate() {
                    row[l] = u32::from_le_bytes(d[4 * w..4 * w + 4].try_into().unwrap());
                }
            }
            // Compare the first output word of all 8 lanes at once; verify candidates fully.
            let mask = unsafe {
                let out = crate::rmd8::ripemd160_x8(&words);
                _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(out[0], _mm256_set1_epi32(t0 as i32))))
            };
            if mask != 0 {
                for l in 0..8 {
                    if mask & (1 << l) != 0 && hash160_c(&px[j + l], &py[j + l], buf) == *target {
                        return Some(j + l);
                    }
                }
            }
            j += 8;
        }
    }
    while j < n {
        if hash160_c(&px[j], &py[j], buf) == *target {
            return Some(j);
        }
        j += 1;
    }
    None
}
