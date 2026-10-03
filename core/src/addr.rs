use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum AddrError {
    BadHex,
    BadKey,
    BadAddress,
}

impl std::fmt::Display for AddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AddrError::BadHex => "invalid hex",
            AddrError::BadKey => "key out of range (must be 1..n-1)",
            AddrError::BadAddress => "not a valid P2PKH address",
        })
    }
}
impl std::error::Error for AddrError {}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&Ripemd160::digest(Sha256::digest(data)));
    out
}

pub fn p2pkh_hash160(p: &AffinePoint, compressed: bool) -> [u8; 20] {
    hash160(p.to_encoded_point(compressed).as_bytes())
}

pub fn address_from_hash160(h: &[u8; 20]) -> String {
    let mut v = Vec::with_capacity(21);
    v.push(0x00);
    v.extend_from_slice(h);
    bs58::encode(v).with_check().into_string()
}

pub fn decode_address(addr: &str) -> Result<[u8; 20], AddrError> {
    let v = bs58::decode(addr).with_check(None).into_vec().map_err(|_| AddrError::BadAddress)?;
    if v.len() != 21 || v[0] != 0 {
        return Err(AddrError::BadAddress);
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&v[1..]);
    Ok(h)
}

pub fn parse_hex32(s: &str) -> Result<[u8; 32], AddrError> {
    let s = s.trim().trim_start_matches("0x");
    if s.is_empty() || s.len() > 64 {
        return Err(AddrError::BadHex);
    }
    let padded = format!("{:0>64}", s);
    let mut out = [0u8; 32];
    hex::decode_to_slice(padded, &mut out).map_err(|_| AddrError::BadHex)?;
    Ok(out)
}

pub fn scalar_from_be(b: &[u8; 32]) -> Result<Scalar, AddrError> {
    let s: Option<Scalar> = Scalar::from_repr((*b).into()).into();
    match s {
        Some(s) if !bool::from(s.is_zero()) => Ok(s),
        _ => Err(AddrError::BadKey),
    }
}

pub fn pubkey_of(b: &[u8; 32]) -> Result<AffinePoint, AddrError> {
    Ok((ProjectivePoint::GENERATOR * scalar_from_be(b)?).to_affine())
}

pub fn wif(key: &[u8; 32], compressed: bool) -> String {
    let mut v = Vec::with_capacity(34);
    v.push(0x80);
    v.extend_from_slice(key);
    if compressed {
        v.push(0x01);
    }
    bs58::encode(v).with_check().into_string()
}

/// 256-bit big-endian add of a u128 offset.
pub fn add_be(base: &[u8; 32], off: u128) -> [u8; 32] {
    let mut out = *base;
    let ob = off.to_be_bytes();
    let mut carry = 0u16;
    for i in 0..32 {
        let idx = 31 - i;
        let o = if i < 16 { ob[15 - i] as u16 } else { 0 };
        let sum = out[idx] as u16 + o + carry;
        out[idx] = sum as u8;
        carry = sum >> 8;
    }
    out
}
