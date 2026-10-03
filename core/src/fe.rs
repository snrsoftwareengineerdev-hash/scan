//! Minimal secp256k1 field arithmetic (p = 2^256 - 2^32 - 977), 4x64 little-endian limbs.
//! Values are kept weakly reduced (< 2^256); `normalize` gives the canonical form.

pub type Fe = [u64; 4];
const K: u64 = 0x1_0000_03D1; // 2^256 mod p
const P: Fe = [0xFFFF_FFFE_FFFF_FC2F, u64::MAX, u64::MAX, u64::MAX];
pub const ZERO: Fe = [0; 4];
pub const ONE: Fe = [1, 0, 0, 0];

#[inline(always)]
fn add_small(r: &mut Fe, k: u64) -> bool {
    let mut c = k;
    for limb in r.iter_mut() {
        let (s, o) = limb.overflowing_add(c);
        *limb = s;
        c = o as u64;
        if c == 0 {
            return false;
        }
    }
    c != 0
}

#[inline(always)]
fn sub_small(r: &mut Fe, k: u64) -> bool {
    let mut b = k;
    for limb in r.iter_mut() {
        let (s, o) = limb.overflowing_sub(b);
        *limb = s;
        b = o as u64;
        if b == 0 {
            return false;
        }
    }
    b != 0
}

#[inline(always)]
pub fn add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut c = 0u64;
    for i in 0..4 {
        let (s1, o1) = a[i].overflowing_add(b[i]);
        let (s2, o2) = s1.overflowing_add(c);
        r[i] = s2;
        c = (o1 | o2) as u64;
    }
    if c != 0 {
        add_small(&mut r, K); // wrapped value is tiny, cannot carry again
    }
    r
}

#[inline(always)]
pub fn sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut br = 0u64;
    for i in 0..4 {
        let (s1, o1) = a[i].overflowing_sub(b[i]);
        let (s2, o2) = s1.overflowing_sub(br);
        r[i] = s2;
        br = (o1 | o2) as u64;
    }
    if br != 0 {
        while sub_small(&mut r, K) {}
    }
    r
}

#[inline(always)]
pub fn mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = t[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            t[i + j] = cur as u64;
            carry = cur >> 64;
        }
        t[i + 4] = carry as u64;
    }
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let cur = t[i] as u128 + (t[i + 4] as u128) * (K as u128) + carry;
        r[i] = cur as u64;
        carry = cur >> 64;
    }
    // carry < 2^34; fold once more
    let mut c = (carry as u64) as u128 * K as u128;
    for limb in r.iter_mut() {
        let cur = *limb as u128 + (c & u64::MAX as u128);
        *limb = cur as u64;
        c = (c >> 64) + (cur >> 64);
        if c == 0 {
            break;
        }
    }
    if c != 0 {
        add_small(&mut r, K);
    }
    r
}

#[inline(always)]
pub fn sqr(a: &Fe) -> Fe {
    mul(a, a)
}

pub fn normalize(a: &Fe) -> Fe {
    let mut r = *a;
    // r < 2^256 < 2p, so one conditional subtraction suffices
    let mut ge = true;
    for i in (0..4).rev() {
        if r[i] != P[i] {
            ge = r[i] > P[i];
            break;
        }
    }
    if ge {
        let mut br = 0u64;
        for i in 0..4 {
            let (s1, o1) = r[i].overflowing_sub(P[i]);
            let (s2, o2) = s1.overflowing_sub(br);
            r[i] = s2;
            br = (o1 | o2) as u64;
        }
    }
    r
}

pub fn from_be(b: &[u8]) -> Fe {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[24 - 8 * i..32 - 8 * i]);
        r[i] = u64::from_be_bytes(w);
    }
    r
}

pub fn to_be(a: &Fe) -> [u8; 32] {
    let n = normalize(a);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[24 - 8 * i..32 - 8 * i].copy_from_slice(&n[i].to_be_bytes());
    }
    out
}

pub fn inv(a: &Fe) -> Fe {
    // a^(p-2) by square-and-multiply over the bits of p-2
    let mut e = P;
    e[0] -= 2;
    let mut r = ONE;
    for i in (0..256).rev() {
        r = sqr(&r);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            r = mul(&r, a);
        }
    }
    r
}

/// Invert all elements in place with one field inversion (Montgomery's trick). Inputs must be non-zero.
pub fn batch_inv(v: &mut [Fe], scratch: &mut Vec<Fe>) {
    scratch.clear();
    let mut acc = ONE;
    for x in v.iter() {
        acc = mul(&acc, x);
        scratch.push(acc);
    }
    let mut inv_acc = inv(&acc);
    for i in (1..v.len()).rev() {
        let x = v[i];
        v[i] = mul(&inv_acc, &scratch[i - 1]);
        inv_acc = mul(&inv_acc, &x);
    }
    if !v.is_empty() {
        v[0] = inv_acc;
    }
}
