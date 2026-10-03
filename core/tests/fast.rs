use scan_core::addr::*;
use scan_core::fast::*;
use scan_core::fe;
use scan_core::range::scan_range;
use std::sync::atomic::AtomicBool;

fn target_for(key: &[u8; 32]) -> [u8; 20] {
    p2pkh_hash160(&pubkey_of(key).unwrap(), true)
}

#[test]
fn field_ops_match_reference() {
    // (p-1)^2 = 1, a * a^-1 = 1, add/sub inverse
    let pm1 = fe::sub(&fe::ZERO, &fe::ONE);
    assert_eq!(fe::normalize(&fe::sqr(&pm1)), fe::ONE);
    let a = fe::from_be(&parse_hex32("deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff").unwrap());
    assert_eq!(fe::normalize(&fe::mul(&a, &fe::inv(&a))), fe::ONE);
    let b = fe::from_be(&parse_hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e").unwrap());
    assert_eq!(fe::normalize(&fe::sub(&fe::add(&a, &b), &b)), fe::normalize(&a));
    let mut v = vec![a, b, fe::ONE];
    let orig = v.clone();
    fe::batch_inv(&mut v, &mut Vec::new());
    for (x, i) in orig.iter().zip(&v) {
        assert_eq!(fe::normalize(&fe::mul(x, i)), fe::ONE);
    }
}

#[test]
fn fast_finds_every_position_in_and_across_batches() {
    let t = Tables::new();
    let start = parse_hex32("a1b2c3d4e5f60718").unwrap();
    for off in [0u128, 1, 511, 512, 513, 1024, 1025, 1026, 2049, 3000] {
        let key = add_be(&start, off);
        let (hit, tested) = scan_fast(&t, &start, 4000, &target_for(&key), &AtomicBool::new(false)).unwrap();
        assert_eq!(hit, Some(key), "offset {off}");
        assert_eq!(tested as u128, off + 1);
    }
}

#[test]
fn fast_matches_reference_on_miss_and_count() {
    let t = Tables::new();
    let start = parse_hex32("123456789abcdef0123456").unwrap();
    let target = [9u8; 20];
    let (h, n) = scan_fast(&t, &start, 2500, &target, &AtomicBool::new(false)).unwrap();
    assert!(h.is_none());
    assert_eq!(n, 2500);
    let key = add_be(&start, 2499);
    let (h, _) = scan_fast(&t, &start, 2500, &target_for(&key), &AtomicBool::new(false)).unwrap();
    let (r, _) = scan_range(&start, 2500, &target_for(&key), false, &AtomicBool::new(false)).unwrap();
    assert_eq!(h, Some(key));
    assert_eq!(r.unwrap().key, key);
}

#[test]
fn fast_solves_puzzle_32_slice() {
    let t = Tables::new();
    let target = decode_address("1FRoHA9xewq7DjrZ1psWJVeTer8gHRqEvR").unwrap();
    let start = parse_hex32("b8620000").unwrap();
    let (h, _) = scan_fast(&t, &start, 1 << 16, &target, &AtomicBool::new(false)).unwrap();
    assert_eq!(hex::encode(h.unwrap()), format!("{:0>64}", "b862a62e"));
}

#[test]
fn fast_ok_gates_small_keys() {
    assert!(!fast_ok(&parse_hex32("10").unwrap()));
    assert!(fast_ok(&parse_hex32("100000").unwrap()));
}
