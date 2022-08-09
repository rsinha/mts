pub type PartyId = usize;
pub type XCoord = usize;
pub type Weight = usize;

pub mod common;
pub mod multiverse_sig;
pub mod bls_sig;

#[allow(dead_code)]
mod utils;
#[allow(dead_code)]
mod polynomial;
#[allow(dead_code)]
mod kzg;
