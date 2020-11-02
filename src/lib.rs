#![feature(min_const_generics)]
#![feature(result_copied)]

use std::convert::TryFrom as _;
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
    chains: Vec<Chain<P>>,
}

#[derive(Copy, Clone, Debug)]
pub struct Chain<const P: usize> {
    /// The first plaintext password (of length P) in the chain
    pass: [u8; P],

    /// The final MD5 hash value in the chain
    hash: [u8; 16],
}

impl<const P: usize> Table<P> {
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let chain_count = reader.read_u64::<byteorder::LittleEndian>()? as usize;
        let chain_length = reader.read_u64::<byteorder::LittleEndian>()? as usize;
        let mut chains = Vec::with_capacity(chain_count);

        let mut pass = [0; P];
        let mut hash = [0; 16];

        for _ in 0..chain_count {
            reader.read_exact(&mut pass)?;
            reader.read_exact(&mut hash)?;
            chains.push(Chain {
                pass,
                hash,
            });
        }

        Ok(Table {
            length: chain_length,
            chains,
        })
    }

    /// Using `seeds` as the start of each chain, write a rainbow table of chain length `length`
    /// to output buffer `writer`.
    pub fn write<W, S>(mut writer: W, seeds: &[S], length: usize) -> io::Result<()>
    where
        W: Send + io::Write,
        S: Sync + AsRef<[u8]>,
    {
        crossbeam::scope(|scope| {
            let (tx, rx) = channel::bounded::<Chain<P>>(100);

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

            seeds
                .par_iter()
                .map(|seed| {
                    // TODO: push responsibility for validating length to caller
                    <&[u8; P]>::try_from(seed.as_ref())
                        .copied()
                        .expect("Provided seed has incorrect length")
                })
                .for_each(|seed| {
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

    pub fn get(&self, target: [u8; 16]) -> Option<[u8; P]> {
        (0..self.length)
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
                    .iter()
                    .filter(|chain| chain.hash == hash)
                    .filter_map(|chain| self.walk(chain, target))
                    .next()
            })
    }

    fn walk(&self, chain: &Chain<P>, target: [u8; 16]) -> Option<[u8; P]> {
        let mut pass = chain.pass;
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

    fn reduce(reduction: usize, hash: [u8; 16]) -> [u8; P] {
        assert!(P <= 16, "This project does not support plaintext passwords longer than 16 bytes.");

        let hash = u128::from_le_bytes(hash);
        let pass = reduction as u128 + (hash >> (128 - (8 * P)));

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
