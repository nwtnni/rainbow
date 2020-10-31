#![feature(min_const_generics)]

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
