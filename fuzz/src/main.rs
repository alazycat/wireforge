//! Self-contained mutation fuzzer for the WireForge parsers.
//!
//! Usage:
//! ```text
//! wireforge-fuzz [--iters N] [--seed S] [--corpus-dir PATH]
//! ```
//!
//! - `--iters`     number of mutation rounds (default 1,000,000)
//! - `--seed`      xorshift64 seed; identical seed + iteration count is
//!                 reproducible across runs
//! - `--corpus-dir` if set, extra seed files are loaded from the given
//!                 directory and discovered crash inputs are saved there
//!
//! Any panic, arithmetic overflow, or slice-out-of-bounds in the parse
//! surfaces ([`surface::run_all`]) aborts the run and writes the
//! offending input to `artifacts/crash-<hash>.bin` for reproduction.

use std::env;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

mod seeds;
mod surface;

const MAX_INPUT: usize = 4096;
const MAX_CORPUS: usize = 4096;

/// xorshift64* — tiny, deterministic, good enough for mutation.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, n)`; `n` must be > 0.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Apply 1–4 random mutations to `data`.
fn mutate(data: &mut Vec<u8>, rng: &mut Rng) {
    if data.is_empty() {
        data.push(rng.next() as u8);
    }
    for _ in 0..1 + rng.below(4) {
        if data.is_empty() {
            data.push(rng.next() as u8);
        }
        match rng.below(7) {
            // Bit flip.
            0 => {
                let i = rng.below(data.len());
                data[i] ^= 1u8 << rng.below(8);
            }
            // Random byte overwrite.
            1 => {
                let i = rng.below(data.len());
                data[i] = rng.next() as u8;
            }
            // Insert a byte.
            2 => {
                let i = rng.below(data.len());
                data.insert(i, rng.next() as u8);
            }
            // Delete a byte.
            3 => {
                let i = rng.below(data.len());
                data.remove(i);
            }
            // Truncate.
            4 => {
                data.truncate(rng.below(data.len()));
            }
            // Extend with a chunk of the input itself (repetition).
            5 => {
                if data.len() < MAX_INPUT {
                    let i = rng.below(data.len());
                    let end = (i + rng.below(64)).min(data.len());
                    data.extend_from_within(i..end);
                }
            }
            // Splice two corpus entries (done by the caller for entry 6,
            // here: clobber a run of bytes).
            _ => {
                let i = rng.below(data.len());
                let end = (i + rng.below(16)).min(data.len());
                for b in &mut data[i..end] {
                    *b = rng.next() as u8;
                }
            }
        }
        if data.len() > MAX_INPUT {
            data.truncate(MAX_INPUT);
        }
    }
}

fn load_corpus_dir(dir: &PathBuf, out: &mut Vec<Vec<u8>>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(bytes) = fs::read(entry.path()) {
                if !bytes.is_empty() && bytes.len() <= MAX_INPUT {
                    out.push(bytes);
                }
            }
        }
    }
}

fn save_crash(dir: &PathBuf, input: &[u8]) -> PathBuf {
    let _ = fs::create_dir_all(dir);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("crash-{}-{}.bin", stamp, input.len()));
    let _ = fs::write(&path, input);
    path
}

fn main() {
    let mut iters: u64 = 1_000_000;
    let mut seed: u64 = 0x5717_E_F00D_u64;
    let mut corpus_dir: Option<PathBuf> = None;

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                i += 1;
                iters = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(iters);
            }
            "--seed" => {
                i += 1;
                seed = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(seed);
            }
            "--corpus-dir" => {
                i += 1;
                corpus_dir = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("unknown argument: {other}");
                eprintln!("usage: wireforge-fuzz [--iters N] [--seed S] [--corpus-dir PATH]");
                exit(2);
            }
        }
        i += 1;
    }

    // Mix wall-clock when the user did not pin a seed, so unattended runs
    // explore different regions. A pinned --seed always wins.
    let effective_seed = if std::env::args().any(|a| a == "--seed") {
        seed
    } else {
        seed ^ SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };

    let mut rng = Rng(effective_seed | 1);
    let mut corpus: Vec<Vec<u8>> = seeds::all().into_iter().map(Vec::from).collect();
    if let Some(dir) = &corpus_dir {
        load_corpus_dir(dir, &mut corpus);
    }

    eprintln!(
        "wireforge-fuzz: iters={} seed={:#018x} corpus={} inputs",
        iters, effective_seed, corpus.len()
    );

    for round in 0..iters {
        let mut input: Vec<u8> = if rng.below(8) == 0 {
            // Fully random blob.
            (0..rng.below(MAX_INPUT)).map(|_| rng.next() as u8).collect()
        } else {
            corpus[rng.below(corpus.len())].clone()
        };

        if rng.below(16) == 0 && corpus.len() > 1 {
            // Splice two corpus entries.
            let a = corpus[rng.below(corpus.len())].clone();
            let b = &corpus[rng.below(corpus.len())];
            let cut = rng.below(a.len() + 1);
            input.truncate(cut);
            input.extend_from_slice(b);
            input.truncate(MAX_INPUT);
        } else {
            mutate(&mut input, &mut rng);
        }
        if input.is_empty() {
            input.push(rng.next() as u8);
        }

        let result = catch_unwind(AssertUnwindSafe(|| surface::run_all(&input)));
        if result.is_err() {
            eprintln!(
                "\nPANIC on iteration {} — input ({} bytes):",
                round,
                input.len()
            );
            eprintln!("{}", hex_dump(&input));
            let path = save_crash(&PathBuf::from("artifacts"), &input);
            eprintln!("saved crash input to {}", path.display());
            exit(101);
        }

        // Grow the corpus with structurally interesting survivors.
        if input.len() >= 4 && corpus.len() < MAX_CORPUS && rng.below(64) == 0 {
            corpus.push(input);
        }

        if round > 0 && round % 100_000 == 0 {
            eprintln!("  ... {round} iterations, {} corpus entries", corpus.len());
        }
    }

    eprintln!(
        "OK: {} iterations, no panics (seed {:#018x})",
        iters, effective_seed
    );
}

fn hex_dump(data: &[u8]) -> String {
    data.chunks(16)
        .map(|row| {
            row.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
