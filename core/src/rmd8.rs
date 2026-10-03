//! 8-lane AVX2 RIPEMD-160 for single-block 32-byte messages (the second half of hash160).
#![cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const RL: [[usize; 16]; 5] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
];
const RR: [[usize; 16]; 5] = [
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
];
const SL: [[i32; 16]; 5] = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
];
const SR: [[i32; 16]; 5] = [
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
];
const KL: [u32; 5] = [0, 0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xA953_FD4E];
const KR: [u32; 5] = [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x7A6D_76E9, 0];

#[inline(always)]
unsafe fn rol(x: __m256i, s: i32) -> __m256i {
    _mm256_or_si256(_mm256_sll_epi32(x, _mm_cvtsi32_si128(s)), _mm256_srl_epi32(x, _mm_cvtsi32_si128(32 - s)))
}

#[inline(always)]
unsafe fn f(round: usize, x: __m256i, y: __m256i, z: __m256i) -> __m256i {
    let ones = _mm256_set1_epi32(-1);
    match round {
        0 => _mm256_xor_si256(_mm256_xor_si256(x, y), z),
        1 => _mm256_or_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z)),
        2 => _mm256_xor_si256(_mm256_or_si256(x, _mm256_xor_si256(y, ones)), z),
        3 => _mm256_or_si256(_mm256_and_si256(x, z), _mm256_andnot_si256(z, y)),
        _ => _mm256_xor_si256(x, _mm256_or_si256(y, _mm256_xor_si256(z, ones))),
    }
}

/// `msgs[w]` holds message word `w` (little-endian u32 of the 32-byte input) for 8 lanes.
/// Returns the 5 state words h0..h4 (lane-parallel).
#[target_feature(enable = "avx2")]
pub unsafe fn ripemd160_x8(words: &[[u32; 8]; 8]) -> [__m256i; 5] {
    let mut x = [_mm256_setzero_si256(); 16];
    for w in 0..8 {
        x[w] = _mm256_loadu_si256(words[w].as_ptr() as *const __m256i);
    }
    x[8] = _mm256_set1_epi32(0x80);
    x[14] = _mm256_set1_epi32(256);

    let h = [0x6745_2301u32, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0].map(|v| _mm256_set1_epi32(v as i32));
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    let (mut a2, mut b2, mut c2, mut d2, mut e2) = (h[0], h[1], h[2], h[3], h[4]);

    for r in 0..5 {
        let kl = _mm256_set1_epi32(KL[r] as i32);
        let kr = _mm256_set1_epi32(KR[r] as i32);
        for j in 0..16 {
            let t = _mm256_add_epi32(a, f(r, b, c, d));
            let t = _mm256_add_epi32(_mm256_add_epi32(t, x[RL[r][j]]), kl);
            let t = _mm256_add_epi32(rol(t, SL[r][j]), e);
            a = e;
            e = d;
            d = rol(c, 10);
            c = b;
            b = t;

            let t = _mm256_add_epi32(a2, f(4 - r, b2, c2, d2));
            let t = _mm256_add_epi32(_mm256_add_epi32(t, x[RR[r][j]]), kr);
            let t = _mm256_add_epi32(rol(t, SR[r][j]), e2);
            a2 = e2;
            e2 = d2;
            d2 = rol(c2, 10);
            c2 = b2;
            b2 = t;
        }
    }
    let t = _mm256_add_epi32(_mm256_add_epi32(h[1], c), d2);
    let n1 = _mm256_add_epi32(_mm256_add_epi32(h[2], d), e2);
    let n2 = _mm256_add_epi32(_mm256_add_epi32(h[3], e), a2);
    let n3 = _mm256_add_epi32(_mm256_add_epi32(h[4], a), b2);
    let n4 = _mm256_add_epi32(_mm256_add_epi32(h[0], b), c2);
    [t, n1, n2, n3, n4]
}
