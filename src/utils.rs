use pairing::group::ff::PrimeField;
use std::ops::*;
use bls12_381::*;
use bls12_381::hash_to_curve::*;
use sha2::{Sha256, Digest};

// fast 64-bit log
// copypasta from https://stackoverflow.com/questions/11376288/fast-computing-of-log2-for-64-bit-integers
const LOG_TABLE: [u64; 64] = [
    63, 0, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54, 33, 42, 3, 61, 51, 37, 40, 49, 18, 28, 20, 55,
    30, 34, 11, 43, 14, 22, 4, 62, 57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13, 21, 56,
    45, 25, 31, 35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5,
];

pub fn log2(mut x: u64) -> u64 {
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    LOG_TABLE[(((x - (x >> 1)) * 0x07EDD5E59A4E28C2) >> 58) as usize]
}

pub fn log2_ceil(x: u64) -> u64 {
    let n = log2(x);
    // if x is a power of two, n is ceiling, otherwise it's n + 1
    if x & (x - 1) == 0 {
        n
    } else {
        n + 1
    }
}

pub fn pad_to_power_of_two<S: PrimeField>(xs: &[S]) -> Vec<S> {
    let n = 1 << log2_ceil(xs.len() as u64) as usize;
    let mut xs: Vec<S> = xs.to_vec();
    if xs.len() != n {
        xs.resize(n, S::zero())
    }
    xs
}

#[cfg(feature = "parallel")]
pub fn chunk_by_num_threads(size: usize) -> usize {
    let num_threads = rayon::current_num_threads();
    if size < num_threads {
        1
    } else {
        size / num_threads
    }
}

pub fn is_power_of_two(n: u64) -> bool {
    n & (n - 1) == 0
}

pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert!(a.len() == b.len());
    let hadamard_product: Vec<Scalar> = a
        .iter()
        .zip(b.iter())
        .map(|(a_i, b_i)| a_i.mul(b_i))
        .collect();

    hadamard_product.iter().fold(Scalar::zero(), |sum, x| sum.add(x))
}

pub fn multi_exp_g1(bases: &[G1Projective], powers: &[Scalar]) -> G1Projective {
    assert!(bases.len() == powers.len());
    let powered : Vec<G1Projective> = bases
        .iter()
        .zip(powers.iter())
        .map(|(x,y)| x.mul(y))
        .collect();
    powered.iter().fold(G1Projective::identity(), |s, a| s.add(a))
}

pub fn multi_exp_g1_fast(bases: &[G1Projective], powers: &[Scalar]) -> G1Projective {
    G1Projective::sum_of_products(bases, powers)
}

pub fn multi_exp_g2(bases: &[G2Projective], powers: &[Scalar]) -> G2Projective {
    assert!(bases.len() == powers.len());
    let powered : Vec<G2Projective> = bases
        .iter()
        .zip(powers.iter())
        .map(|(x,y)| x.mul(y))
        .collect();
    powered.iter().fold(G2Projective::identity(), |s, a| s.add(a))
}

pub fn multi_exp_g2_fast(bases: &[G2Projective], powers: &[Scalar]) -> G2Projective {
    G2Projective::sum_of_products(bases, powers)
}

pub const DOMAIN_G1: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DOMAIN_G1)
}

pub const DOMAIN_G2: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
pub fn hash_to_g2(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DOMAIN_G2)
}

pub fn commit_in_g1(generator: &G1Projective, value: &Scalar) -> G1Projective {
    generator.mul(value)
}

pub fn commit_in_g2(generator: &G2Projective, value: &Scalar) -> G2Projective {
    generator.mul(value)
}

pub fn convert_gt_to_256_bit_hash(point: &Gt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(format!("{:?}", point));

    // read hash digest and consume hasher
    let aes_key : [u8; 32] = hasher
        .finalize()[..]
        .try_into()
        .expect("slice with incorrect length");
    return aes_key;
}
