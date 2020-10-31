#![feature(min_const_generics)]
#![feature(result_copied)]

use std::array;
use std::convert::TryFrom as _;
use std::io;
use std::mem;

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
pub struct Table<'mem, const P: usize>(&'mem [Chain<P>]);

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
    pub fn write<'password, W, S>(mut writer: W, seeds: S, length: usize) -> Result<(), Error>
    where
        W: io::Write,
        S: IntoIterator<Item = &'password [u8]>,
    {
        let align = mem::align_of::<Chain<P>>();
        let padding = match P % align {
        | 0 => vec![],
        | bytes => vec![0; align - bytes],
        };

        for seed in seeds {
            let mut pass = <&'password [u8; P]>::try_from(seed)
                .copied()
                .map_err(|source| Error::PasswordLength { expected: P, source })?;

            let mut hash = md5::compute(&pass).0;

            for reduction in 0..length {
                pass = Self::reduce(reduction, hash);
                hash = md5::compute(pass).0;
            }

            writer.write_all(&pass)?;
            writer.write_all(&padding)?;
            writer.write_all(&hash)?;
        }

        Ok(())
    }

    fn reduce(reduction: usize, hash: [u8; 16]) -> [u8; P] {
        assert!(P <= 16, "This project does not support plaintext passwords longer than 16 bytes.");

        let hash = u128::from_be_bytes(hash);
        let pass = reduction as u128 + hash % 8u128.pow(P as u32);

        let mut reduced = [0; P];
        for (src, dst) in pass.to_be_bytes().iter().zip(&mut reduced) {
            *dst = *src;
        }
        reduced
    }
}
