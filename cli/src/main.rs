mod kang;

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use scan_core::addr::*;
use scan_core::fast::{fast_ok, scan_fast, Tables};
use scan_core::range::{scan_range, Hit};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

const CHUNK: u64 = 1 << 20;

#[derive(Deserialize)]
struct Puzzle {
    id: u32,
    address: String,
    start: String,
}

#[derive(Parser)]
#[command(name = "scan", about = "Bitcoin puzzle challenge range scanner (puzzle addresses only)")]
struct Cli {
    #[arg(long, default_value = "data/puzzles.json", global = true)]
    data: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan part of a puzzle's range for its published address.
    Solve {
        /// Puzzle number (1-160)
        puzzle: u32,
        /// Offset into the puzzle range, in keys (default 0)
        #[arg(long, default_value_t = 0)]
        offset: u128,
        /// Keys to test this run (default 2^30)
        #[arg(long, default_value_t = 1 << 30)]
        keys: u64,
        /// Start at a random offset inside the range
        #[arg(long)]
        random: bool,
        /// Also test uncompressed public keys
        #[arg(long)]
        uncompressed: bool,
    },
    /// Pollard kangaroo simulation on a random key of the given size (validates the engine)
    KangarooTest {
        #[arg(long, default_value_t = 40)]
        bits: u32,
        #[arg(long, default_value_t = 256.0)]
        jump_scale: f64,
    },
    /// Pollard kangaroo for a puzzle whose PUBLIC KEY is known. The key must hash to the puzzle's address.
    Kangaroo {
        puzzle: u32,
        #[arg(long)]
        pubkey: String,
        #[arg(long, default_value_t = 256.0)]
        jump_scale: f64,
        #[arg(long, default_value_t = 1u64 << 40)]
        max_ops: u64,
    },
    /// Throughput benchmark
    Bench {
        #[arg(long, default_value_t = 8_000_000)]
        keys: u64,
    },
}

fn load(path: &str, id: u32) -> Result<Puzzle, Box<dyn std::error::Error>> {
    let v: Vec<Puzzle> = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    v.into_iter().find(|p| p.id == id).ok_or_else(|| format!("puzzle {id} not in dataset").into())
}

fn parallel_scan(start: &[u8; 32], count: u64, target: &[u8; 20], unc: bool) -> (Option<Hit>, u64) {
    let stop = AtomicBool::new(false);
    let tested = AtomicU64::new(0);
    // Fast batched-inversion path handles compressed keys away from the tiny-key edge cases.
    let tables = (!unc && fast_ok(start)).then(Tables::new);
    let hit = (0..count.div_ceil(CHUNK)).into_par_iter().find_map_any(|i| {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let n = CHUNK.min(count - i * CHUNK);
        let begin = add_be(start, (i * CHUNK) as u128);
        let (h, t) = match &tables {
            Some(t) => {
                let (k, t) = scan_fast(t, &begin, n, target, &stop).ok()?;
                (k.map(|key| Hit { key, compressed: true }), t)
            }
            None => scan_range(&begin, n, target, unc, &stop).ok()?,
        };
        tested.fetch_add(t, Ordering::Relaxed);
        if h.is_some() {
            stop.store(true, Ordering::Relaxed);
        }
        h
    });
    (hit, tested.load(Ordering::Relaxed))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::KangarooTest { bits, jump_scale } => {
            let start = 1u128 << (bits - 1);
            let k = start + rand::Rng::gen_range(&mut rand::thread_rng(), 0..start);
            let q = (k256::ProjectivePoint::GENERATOR * k256::Scalar::from(k)).to_affine();
            let t = Instant::now();
            let o = kang::solve(&q, start, bits, jump_scale, 1 << 42);
            let s = t.elapsed().as_secs_f64();
            let sw = ((1u128 << (bits - 1)) as f64).sqrt();
            println!("bits {bits}: {} ops = {:.2}·sqrt(W) in {s:.2}s ({:.2} Mops/s)", o.ops, o.ops as f64 / sw, o.ops as f64 / s / 1e6);
            match o.key {
                Some(f) if f == k => println!("OK recovered {f:#x}"),
                Some(f) => println!("WRONG {f:#x} != {k:#x}"),
                None => println!("not found"),
            }
        }
        Cmd::Kangaroo { puzzle, pubkey, jump_scale, max_ops } => {
            use k256::elliptic_curve::sec1::FromEncodedPoint;
            let p = load(&cli.data, puzzle)?;
            let bytes = hex::decode(pubkey.trim())?;
            let ep = k256::EncodedPoint::from_bytes(&bytes).map_err(|_| "bad public key encoding")?;
            let q = Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(&ep)).ok_or("public key not on curve")?;
            let want = decode_address(&p.address)?;
            if scan_core::addr::hash160(&bytes) != want {
                return Err("public key does not match this puzzle's address".into());
            }
            if !(2..=126).contains(&puzzle) {
                return Err("kangaroo supports puzzles 2..=126 (u128 arithmetic)".into());
            }
            let start = 1u128 << (puzzle - 1);
            println!("kangaroo on puzzle {puzzle}: range 2^{} wide, expected ~2.5·2^{:.1} ops", puzzle - 1, (puzzle - 1) as f64 / 2.0);
            let t = Instant::now();
            let o = kang::solve(&q, start, puzzle, jump_scale, max_ops);
            println!("{} ops in {:.1}s", o.ops, t.elapsed().as_secs_f64());
            match o.key {
                Some(k) => println!("FOUND key {k:032x}"),
                None => println!("not found within max_ops"),
            }
        }
        Cmd::Bench { keys } => {
            let t = Instant::now();
            let (_, n) = parallel_scan(&parse_hex32("8000000000000000000000")?, keys, &[0u8; 20], false);
            let s = t.elapsed().as_secs_f64();
            println!("{n} keys in {s:.2}s = {:.3} Mkeys/s on {} threads", n as f64 / s / 1e6, rayon::current_num_threads());
        }
        Cmd::Solve { puzzle, offset, keys, random, uncompressed } => {
            let p = load(&cli.data, puzzle)?;
            let start32 = parse_hex32(&p.start)?;
            // Offsets are u128; for puzzles above 129 bits only the low 2^127 of the range is addressable.
            let span: u128 = 1u128 << (p.id.saturating_sub(1)).min(127);
            let off = if random { rand::Rng::gen_range(&mut rand::thread_rng(), 0..span.max(1)) } else { offset };
            let begin = add_be(&start32, off);
            let target = decode_address(&p.address)?;
            println!("puzzle {} {} | offset {off:#x} | {keys} keys", p.id, p.address);
            let t = Instant::now();
            let (hit, n) = parallel_scan(&begin, keys, &target, uncompressed);
            let s = t.elapsed().as_secs_f64();
            println!("tested {n} keys in {s:.2}s ({:.3} Mkeys/s)", n as f64 / s / 1e6);
            match hit {
                Some(h) => println!("FOUND key {}\nWIF   {}", hex::encode(h.key), wif(&h.key, h.compressed)),
                None => println!("not found in this slice"),
            }
        }
    }
    Ok(())
}
