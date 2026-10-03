#![cfg(target_arch = "x86_64")]
use ripemd::{Digest, Ripemd160};
use scan_core::rmd8::ripemd160_x8;

#[test]
fn avx2_ripemd_matches_reference() {
    if !is_x86_feature_detected!("avx2") {
        return;
    }
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..200 {
        let mut msgs = [[0u8; 32]; 8];
        let mut words = [[0u32; 8]; 8];
        for l in 0..8 {
            for b in msgs[l].iter_mut() {
                *b = next() as u8;
            }
            for w in 0..8 {
                words[w][l] = u32::from_le_bytes(msgs[l][4 * w..4 * w + 4].try_into().unwrap());
            }
        }
        let out = unsafe { ripemd160_x8(&words) };
        for l in 0..8 {
            let want = Ripemd160::digest(msgs[l]);
            for k in 0..5 {
                let mut lanes = [0u32; 8];
                unsafe { core::arch::x86_64::_mm256_storeu_si256(lanes.as_mut_ptr() as *mut _, out[k]) };
                assert_eq!(lanes[l].to_le_bytes(), want[4 * k..4 * k + 4], "lane {l} word {k}");
            }
        }
    }
}
