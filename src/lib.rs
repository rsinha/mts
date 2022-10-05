use bls12_381::{G1Projective, Scalar};
use std::collections::{BTreeMap};
use std::rc::Rc;


pub type UniverseId = [u8; 32];
/// PartyId denotes the party's unique identifier, which is typically derived from the signing pubkeyß
pub type PartyId = usize;
pub type XCoord = usize;

/// Weight represents the number of weight units assigned to a party
pub type Weight = usize;

/// PartySecret is the 256-bit secret held by each party
pub type PartySecret = Scalar;

/// PartyPublicKey denotes the public component of each share held by a party
pub type PartyPublicKey = G1Projective;

/// AddressBook maps each party to its weight and vector of public keys
type AddressBook = BTreeMap<PartyId, (Weight, Rc<Vec<PartyPublicKey>>)>;

pub mod universe;
pub mod common;
//pub mod multiverse_sig;
//pub mod bls_sig;
pub mod mts;

//lets allow dead code from "library" implementations
#[allow(dead_code)]
mod utils;
#[allow(dead_code)]
mod polynomial;
#[allow(dead_code)]
mod kzg;
