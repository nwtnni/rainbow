#![feature(min_const_generics)]
#![feature(result_copied)]

use std::collections::HashMap;
use std::io;
use std::io::Write as _;

use byteorder::ReadBytesExt as _;
use byteorder::WriteBytesExt as _;
use crossbeam::channel;
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct Table<const P: usize> {
    /// Length of each chain, i.e. the number of reduction + hash cycles performed
    length: usize,
    chains: HashMap<[u8; 16], [u8; P]>,
}

#[derive(Copy, Clone, Debug)]
pub struct Chain<const P: usize> {
    /// The first plaintext password (of length P) in the chain
    pass: [u8; P],

    /// The final MD5 hash value in the chain
    hash: [u8; 16],
}

impl<const P: usize> Table<P> {
    /// Load a table from the provided `reader`. Expects a table serialized with `Table::write`.
    ///
    /// Note: the generic type argument `P` must match the plaintext length stored in `reader`,
    /// or else all lookups will quietly fail (i.e. without errors).
    ///
    /// There may be fewer than `chain_count` chains at the end of deserialization, since we
    /// merge colliding chains into a `HashMap`.
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let chain_count = reader.read_u64::<byteorder::LittleEndian>()? as usize;
        let chain_length = reader.read_u64::<byteorder::LittleEndian>()? as usize;
        let mut chains = HashMap::with_capacity(chain_count);

        let mut pass = [0; P];
        let mut hash = [0; 16];

        for _ in 0..chain_count {
            reader.read_exact(&mut pass)?;
            reader.read_exact(&mut hash)?;
            chains.insert(hash, pass);
        }

        Ok(Table {
            length: chain_length,
            chains,
        })
    }

    /// Using `seeds` as the start of each chain, write a rainbow table of chain length `length`
    /// to output buffer `writer`.
    ///
    /// The serialization format is straightforward:
    ///
    /// ```txt
    /// chain_count: 8B
    /// chain_length: 8B
    /// (
    ///   chain: PB + 16B
    /// )*
    /// ```
    ///
    /// Unfortunately, it does not include the plaintext length: because we're using const
    /// generics for array length, the plaintext length must be known before we call `Table::read`.
    pub fn write<W: io::Write + Send>(mut writer: W, seeds: &[&[u8; P]], length: usize) -> io::Result<()> {
        crossbeam::scope(|scope| {
            // Arbitrary channel capacity for backpressure
            let (tx, rx) = channel::bounded::<Chain<P>>(100);

            // This thread is responsible for writing chains to disk
            // (and reporting progress via `stdout`).
            scope.spawn(move |_| -> io::Result<()> {
                writer.write_u64::<byteorder::LittleEndian>(seeds.len() as u64)?;
                writer.write_u64::<byteorder::LittleEndian>(length as u64)?;

                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                let mut counter = 0;

                while let Ok(chain) = rx.recv() {
                    counter += 1;
                    writer.write_all(&chain.pass)?;
                    writer.write_all(&chain.hash)?;
                    write!(
                        &mut stdout,
                        "\x1B[2K\x1B[1GGenerating chain {}/{} ({:.2}%)...",
                        counter,
                        seeds.len(),
                        (counter as f32 / seeds.len() as f32) * 100.0,
                    )?;
                    stdout.flush()?;
                }

                Ok(())
            });

            // These threads are responsible for computing the reduction and
            // hash functions across each chain, starting from the initial values.
            //
            // The initial value and final hash are sent to the writer thread for serialization.
            seeds
                .par_iter()
                .for_each(|&&seed| {
                    let mut pass = seed;
                    let mut hash = md5::compute(&pass).0;

                    for reduction in 0..length {
                        pass = Self::reduce(reduction, hash);
                        hash = md5::compute(pass).0;
                    }

                    tx.send(Chain { pass: seed, hash }).expect("[INTERNAL ERROR]: reciever dropped");
                })

        }).expect("[INTERNAL ERROR]: chain generation panicked");

        Ok(())
    }

    /// Attempt to find a plaintext that hashes to `target` in this rainbow table.
    ///
    /// Rainbow tables use a different reduction function per chain link to reduce
    /// collisions, but this makes lookup more computationally expensive. Consider
    /// the following chain:
    ///
    /// ```txt
    /// +--------+         +--------+          +--------+         +--------+          +--------+         +--------+
    /// | pass-0 | -- H -> | hash-0 | -- R₀ -> | pass-1 | -- H -> | hash-1 | -- R₁ -> | pass-2 | -- H -> | hash-2 |
    /// +--------+         +--------+          +--------+         +--------+          +--------+         +--------+
    /// chain.pass                                                                                       chain.hash
    /// ```
    ///
    /// Suppose we have some target hash `hash-t`. Assume `hash-t` is in our chain.
    /// Then we have three cases:
    ///
    /// 1. `hash-t = hash-2`: compare `hash-t` to `chain.hash` and find a match
    /// 2. `hash-t = hash-1`: compare `hash-t |> R₁ |> H` to `chain.hash` and find a match
    /// 3. `hash-t = hash-0`: compare `hash-t |> R₀ |> H |> R₁ |> H` to `chain.hash` and find a match
    ///
    /// Because these cases don't share a common prefix, lookup time grows quadratically
    /// with chain length. But because chains are independent from one another, lookup
    /// is easily parallelizable and grows linearly with chain count.
    pub fn get(&self, target: [u8; 16]) -> Option<[u8; P]> {
        (0..self.length + 1)
            .into_par_iter()
            .rev()
            .find_map_any(|start| {
                let mut pass;
                let mut hash = target;

                for reduction in start..self.length {
                    pass = Self::reduce(reduction, hash);
                    hash = md5::compute(pass).0;
                }

                self.chains
                    .get(&hash)
                    .copied()
                    .and_then(|pass| self.walk(pass, target))
            })
    }

    /// Given a candidate chain beginning with `pass`, find the plaintext in the chain that
    /// hashes to `target`, if it exists.
    ///
    /// Like chain construction, we walk along the chain by alternating hashing and reduction
    /// functions, starting from `chain.pass`. If a hash matches the target hash, then we can
    /// return the immediately preceding plaintext.
    ///
    /// ```txt
    /// +--------+         +--------+          +--------+         +--------+           +--------+         +--------+
    /// | pass-0 | -- H -> | hash-0 | -- R₀ -> | pass-1 | -- H -> | hash-1 | -- ... -> | pass-t | -- H -> | hash-t |
    /// +--------+         +--------+          +--------+         +--------+           +--------+         +--------+
    /// chain.pass                                                                       return             target
    /// ```
    fn walk(&self, mut pass: [u8; P], target: [u8; 16]) -> Option<[u8; P]> {
        let mut hash = md5::compute(pass).0;

        for reduction in 0..self.length {
            if hash == target {
                return Some(pass);
            }
            pass = Self::reduce(reduction, hash);
            hash = md5::compute(pass).0;
        }

        None
    }

    /// Reduce `hash` to a `P`-byte plaintext using the `reduction`th function from the family of reduction functions.
    /// The plaintext is restricted to valid ASCII characters from the set `a-zA-Z0-9_.`.
    ///
    /// This family of functions behaves as follows:
    /// - Add `reduction` to `hash`
    /// - Take the bottom `P` bytes of the result
    /// - Use a table to convert each byte to valid ASCII
    ///
    /// We use `u128` for simplicity, but this restricts us to a maximum of 16-byte plaintexts.
    fn reduce(reduction: usize, hash: [u8; 16]) -> [u8; P] {
        assert!(P <= 16, "This project does not support plaintext passwords longer than 16 bytes.");

        let hash = u128::from_le_bytes(hash);
        let pass = (reduction as u128 + hash) & ((1 << (8 * P)) - 1);

        let mut reduced = [0; P];
        for (dst, src) in reduced.iter_mut().zip(&pass.to_le_bytes()) {
            static TABLE: [u8; 64] = [
                b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm',
                b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',

                b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M',
                b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',

                b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'_', b'.',
            ];

            *dst = TABLE[(*src & 0b0011_1111) as usize];
        }
        reduced
    }
}
