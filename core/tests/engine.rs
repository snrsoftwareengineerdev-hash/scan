use scan_core::addr::*;
use scan_core::range::scan_range;
use std::sync::atomic::AtomicBool;

#[test]
fn derives_key_one() {
    let k = parse_hex32("1").unwrap();
    let h = p2pkh_hash160(&pubkey_of(&k).unwrap(), true);
    assert_eq!(address_from_hash160(&h), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    assert_eq!(wif(&k, true), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
}

#[test]
fn add_be_carries_across_bytes() {
    let b = parse_hex32("ffffffff").unwrap();
    assert_eq!(hex::encode(add_be(&b, 1)), format!("{:0>64}", "100000000"));
    let big = add_be(&[0u8; 32], u128::MAX);
    assert_eq!(&big[16..], &[0xff; 16]);
}

#[test]
fn finds_solved_puzzle_25_inside_a_window() {
    // Puzzle 25: key 0x1fa5ee5, public address from the challenge.
    let target = decode_address("15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP").unwrap();
    let start = parse_hex32("1fa5000").unwrap();
    let (hit, tested) = scan_range(&start, 4096, &target, false, &AtomicBool::new(false)).unwrap();
    assert_eq!(hex::encode(hit.unwrap().key), format!("{:0>64}", "1fa5ee5"));
    assert!(tested <= 4096);
}

#[test]
fn reports_miss_and_honours_count() {
    let target = [7u8; 20];
    let (hit, tested) = scan_range(&parse_hex32("1000000").unwrap(), 2500, &target, true, &AtomicBool::new(false)).unwrap();
    assert!(hit.is_none());
    assert_eq!(tested, 2500);
}

#[test]
fn rejects_invalid_inputs() {
    assert!(parse_hex32("").is_err());
    assert!(scalar_from_be(&[0u8; 32]).is_err());
    assert!(decode_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMX").is_err());
}
