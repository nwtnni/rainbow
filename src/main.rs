use std::fs;
use std::io;
use std::path;
use std::process;
use std::str;

use anyhow::anyhow;
use anyhow::Context as _;
use structopt::StructOpt;

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

        /// Path to write rainbow table to
        #[structopt(short, long)]
        path: path::PathBuf,
    },

    /// Look up a hash using a corresponding rainbow table
    Search {
        /// Path to read rainbow table from
        #[structopt(short, long)]
        path: path::PathBuf,

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
    | Command::Create { chain_count, chain_length, path } => {
        let seeds = (0..chain_count)
            .map(|seed| seed as u64)
            .map(|seed| seed.to_le_bytes())
            .collect::<Vec<_>>();

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)
            .with_context(|| anyhow!("Could not open file for writing: '{}'", path.display()))
            .map(io::BufWriter::new)?;

        rainbow::Table::<8>::write(&mut file, &*seeds, chain_length)?;
    }
    | Command::Search { path, hash } => {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| anyhow!("Could not open file for reading: '{}'", path.display()))
            .map(io::BufReader::new)?;

        let table = rainbow::Table::<8>::read(&mut file)?;

        match table.get(hash) {
        | None => process::exit(1),
        | Some(pass) => {
            match str::from_utf8(&pass) {
            | Ok(string) => println!("{}", string),
            | Err(_) => println!("{:X?}", pass),
            }
        }
        }
    }
    }
    Ok(())
}
