#![feature(min_const_generics)]

use std::convert::TryFrom as _;
use std::fs;
use std::io;
use std::path;
use std::process;
use std::str;

use anyhow::anyhow;
use anyhow::Context as _;
use structopt::StructOpt;

static SEEDS_05: &str = include_str!("../data/passwords-05.txt");
static SEEDS_06: &str = include_str!("../data/passwords-06.txt");

#[derive(StructOpt)]
enum Command {
    /// Generate a rainbow table and serialize it to disk
    Create {
        /// Number of rainbow chains
        #[structopt(long)]
        chain_count: usize,

        /// Length of each rainbow chain
        #[structopt(long)]
        chain_length: usize,

        /// Length of encoded passwords in bytes
        #[structopt(long)]
        pass_length: usize,

        /// Path to write rainbow table to
        #[structopt(short, long)]
        path: path::PathBuf,
    },

    /// Look up a hash using a corresponding rainbow table
    Search {
        /// Path to read rainbow table from
        #[structopt(short, long)]
        path: path::PathBuf,

        /// Length of encoded passwords in bytes
        #[structopt(long)]
        pass_length: usize,

        /// Hash to search for
        #[structopt(parse(try_from_str = from_hex))]
        hash: [u8; 16],
    },
}

fn from_hex(string: &str) -> anyhow::Result<[u8; 16]> {
    // Elsewhere, we use little-endian byte order, but the input hash
    // will be big-endian. We do a swap here in order to correct this.
    u128::from_str_radix(string, 16)
        .map(u128::to_be_bytes)
        .with_context(|| anyhow!("Expected MD5 sum in hexadecimal notation, but found: '{}'", string))
}

fn main() -> anyhow::Result<()> {
    match Command::from_args() {
    | Command::Create { chain_count, chain_length, pass_length, path } => {
        match pass_length {
        | 5 => create::<5>(&path, SEEDS_05, chain_count, chain_length)?,
        | 6 => create::<6>(&path, SEEDS_06, chain_count, chain_length)?,
        | _ => return Err(anyhow!("Only plaintext lengths of 5 or 6 bytes are supported currently for demonstration")),
        }
    }
    | Command::Search { path, pass_length, hash } => {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| anyhow!("Could not open file for reading: '{}'", path.display()))
            .map(io::BufReader::new)?;

        let pass = match pass_length {
        | 5 => rainbow::Table::<5>::read(&mut file)?.get(hash).map(Vec::from),
        | 6 => rainbow::Table::<6>::read(&mut file)?.get(hash).map(Vec::from),
        | _ => return Err(anyhow!("Only plaintext lengths of 5 or 6 bytes are supported currently for demonstration")),
        };

        match pass {
        | None => process::exit(1),
        | Some(pass) => {
            match str::from_utf8(&pass) {
            | Ok(string) => println!("{}", string),
            | _ => println!("{:X?}", pass),
            }
        }
        }
    }
    }
    Ok(())
}

fn create<const P: usize>(
    path: &path::Path,
    seeds: &str,
    chain_count: usize,
    chain_length: usize,
) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&path)
        .with_context(|| anyhow!("Could not open file for writing: '{}'", path.display()))
        .map(io::BufWriter::new)?;

    let seeds = seeds
        .split_whitespace()
        .map(|seed| seed.as_bytes())
        .map(|seed| <&[u8; P]>::try_from(seed).unwrap())
        .take(chain_count)
        .collect::<Vec<_>>();

    rainbow::Table::<P>::write(&mut file, &*seeds, chain_length)?;
    Ok(())
}
