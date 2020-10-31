#![feature(min_const_generics)]
#![feature(result_copied)]

use std::array;
use std::convert::TryFrom as _;
use std::fs;
use std::io;
use std::slice;
use std::mem;

use byteorder::ReadBytesExt as _;
use byteorder::WriteBytesExt as _;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    IO(#[from] io::Error),

    #[error("Expected plaintext password of length {}", expected)]
    PasswordLength {
        expected: usize,
        #[source]
        source: array::TryFromSliceError,
    },
}

#[derive(Copy, Clone, Debug)]
pub struct Table<'mem, const P: usize> {
    /// Length of each chain, i.e. the number of reduction + hash cycles performed
    length: usize,
    chains: &'mem [Chain<P>],
}

#[repr(C)]
#[repr(align(8))]
#[derive(Copy, Clone, Debug)]
pub struct Chain<const P: usize> {
    /// The first plaintext password (of length P) in the chain
    pass: [u8; P],

    /// The final MD5 hash value in the chain
    hash: [u8; 16],
}

impl<'mem, const P: usize> Table<'mem, P> {
    pub fn read(file: &'mem mut fs::File) -> Result<Self, Error> {
        let chain_count = file.read_u64::<byteorder::LittleEndian>()? as usize;
        let chain_length = file.read_u64::<byteorder::LittleEndian>()? as usize;
        let chains = unsafe {
            slice::from_raw_parts(
                memmap::MmapOptions::new()
                    .offset(16)
                    .map(file)?
                    .as_ptr()
                    as *const Chain<P>,
                chain_count,
            )
        };

        Ok(Table {
            length: chain_length,
            chains,
        })
    }

    /// Using `seeds` as the start of each chain, write a rainbow table of chain length `length`
    /// to output buffer `writer`.
    pub fn write<W, S>(mut writer: W, seeds: &[S], length: usize) -> Result<(), Error>
    where
        W: io::Write,
        S: AsRef<[u8]>,
    {
        let align = mem::align_of::<Chain<P>>();
        let padding = match P % align {
        | 0 => vec![],
        | bytes => vec![0; align - bytes],
        };

        writer.write_u64::<byteorder::LittleEndian>(seeds.len() as u64)?;
        writer.write_u64::<byteorder::LittleEndian>(length as u64)?;

        for seed in seeds {
            let mut pass = <&[u8; P]>::try_from(seed.as_ref())
                .copied()
                .map_err(|source| Error::PasswordLength { expected: P, source })?;

            let mut hash = md5::compute(&pass).0;

            writer.write_all(&pass)?;
            writer.write_all(&padding)?;

            for reduction in 0..length {
                pass = Self::reduce(reduction, hash);
                hash = md5::compute(pass).0;
            }

            writer.write_all(&hash)?;
        }

        Ok(())
    }

    fn reduce(reduction: usize, hash: [u8; 16]) -> [u8; P] {
        assert!(P <= 16, "This project does not support plaintext passwords longer than 16 bytes.");

        let hash = u128::from_le_bytes(hash);
        let pass = reduction as u128 + hash % 8u128.pow(P as u32);

        let mut reduced = [0; P];
        for (src, dst) in pass.to_le_bytes().iter().zip(&mut reduced) {
            *dst = *src;
        }
        reduced
    }
}
