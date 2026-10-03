use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;
fn main() {
    let n = 5_000_000u32;
    let mut b = [2u8; 33];
    let mut s = 0u8;
    let t = Instant::now();
    for i in 0..n { b[1] = i as u8; b[2] = (i >> 8) as u8; s ^= black_box(Sha256::digest(black_box(&b)))[0]; }
    let a = t.elapsed().as_secs_f64() / n as f64 * 1e9;
    let h = [7u8; 32];
    let t = Instant::now();
    for i in 0..n { let mut x = h; x[0] = i as u8; x[1] = (i>>8) as u8; s ^= black_box(Ripemd160::digest(black_box(&x)))[0]; }
    let r = t.elapsed().as_secs_f64() / n as f64 * 1e9;
    println!("sha256(33B) {a:.0} ns   ripemd160(32B) {r:.0} ns   ({s})");
}
