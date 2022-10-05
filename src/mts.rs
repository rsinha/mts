use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use pairing::group::{Curve};

use ff::*;
use rand::{thread_rng};
use std::collections::{BTreeMap};
use std::ops::{Add, Mul, Neg};

use crate::polynomial::*;
use crate::kzg::*;
use crate::utils;
use crate::universe::*;
use crate::common::sig_utils;
use crate::{XCoord, UniverseId, PartyId, Weight, PartyPublicKey, AddressBook};

pub struct MTSUniverseCreationMessage {
    pub blinded_evals: Vec<G1Projective>,
    pub blind_commitment: G2Projective,
}

pub struct MTSUniversePublicParams {
    pub evals: Vec<G1Projective>,
    pub blinded_evals: Vec<G1Projective>,
}

pub struct MTSUniverseVerificationKey {
    pub vk_0: G1Projective,
    pub vk_1: G2Projective,
}

pub struct MTSPartialSignature {
    pub signer_id: PartyId,
    pub sig_elements: Vec<G2Projective>
}

pub struct MTSFullSignature {
    sigma_prime: G2Projective,
    sigma_0: G1Projective,
    sigma_1: G1Projective
}

// returns points in the exponents for {0, w+1..2w-t}
fn compute_universe_public_points(
    universe: &Universe) -> (G1Projective, Vec<G1Projective>) {
    let w = universe.get_total_weight();
    let t = universe.get_threshold();

    //compute x-coordinates of all signer points (used to compute lagrange coeffs)
    let _par_xs: Vec<XCoord> = (1..w+1).collect();
    let par_xs: Vec<Scalar> = _par_xs.iter().map(|&x| Scalar::from(x as u64)).collect();

    let _pub_xs: Vec<XCoord> = ((w + 1)..(2 * w - t + 1)).collect();
    let pub_xs: Vec<Scalar> = _pub_xs.iter().map(|&x| Scalar::from(x as u64)).collect();

    let pub_keys: Vec<G1Projective> = sig_utils::compute_universe_pub_keys(&universe);

    let mut pub_points: Vec<G1Projective> = Vec::new();
    //TODO: use sub-product tree optimization
    for x in pub_xs {
        //compute lagrange coefficients
        let λs: Vec<Scalar> = Polynomial::lagrange_coefficients_naive(par_xs.as_slice(), &x);
        let pk = utils::multi_exp_g1_fast(pub_keys.as_slice(), λs.as_slice());
        pub_points.push(pk);
    }

    //compute point at 0
    let λs: Vec<Scalar> = Polynomial::lagrange_coefficients_naive(
        par_xs.as_slice(),
        &Scalar::from(0));
    let pk = utils::multi_exp_g1_fast(pub_keys.as_slice(), λs.as_slice());

    (pk, pub_points)
}

/// public points are optional
fn blind_points(
    public_points: &Vec<G1Projective>) -> (Vec<G1Projective>, G2Projective)  {

    //sample random blinding factor
    let mut rng = thread_rng();
    let k = Scalar::random(&mut rng);

    let evals = public_points.iter().map(|y| utils::commit_in_g1(y, &k)).collect();

    let generator: G2Projective = utils::get_generator_in_g2();
    let g2_blinded = utils::commit_in_g2(&generator, &k);

    (evals, g2_blinded)
}




/// secret is 256-bit value, and num_pubkeys is the number of desired public keys
/// for an 8-bit max weight, num_pubkeys should be set to 256
pub fn publish_pubkeys(
    secret: &Scalar,
    num_pubkeys: usize) -> Vec<G1Projective> {
    let generator: G1Projective = utils::get_generator_in_g1();
    let mut pks = Vec::new();
    for i in 0..num_pubkeys {
        //TODO: maybe better to make this PRG? Need to analyze security here.
        let sk_i = secret + Scalar::from(i as u64);
        let pk_i = utils::commit_in_g1(&generator, &sk_i);

        pks.push(pk_i)
    }
    pks
}

pub fn publish_universe_setup_msg(
    universe: &Universe) -> MTSUniverseCreationMessage {
    let (_, evals_0) = compute_universe_public_points(universe);
    let (evals_1, com) = blind_points(&evals_0);
    MTSUniverseCreationMessage { blinded_evals: evals_1, blind_commitment: com }
}

pub fn compute_universe_pp(
    universe: &Universe,
    msgs: &[MTSUniverseCreationMessage]) -> (MTSUniversePublicParams, MTSUniverseVerificationKey) {
    let w = universe.get_total_weight();
    let t = universe.get_threshold();

    let one_g1 = utils::commit_in_g1(&utils::get_generator_in_g1(), &Scalar::from(0));
    let one_g2 = utils::commit_in_g2(&utils::get_generator_in_g2(), &Scalar::from(0));


    let (pk, evals_0) = compute_universe_public_points(universe);
    let mut evals_1: Vec<G1Projective> = Vec::new();
    for i in 0..(w - t) {
        let evals_1_i = msgs.iter().fold(one_g1, |sum, m| sum.add(m.blinded_evals.get(i).unwrap()));
        evals_1.push(evals_1_i);
    }
    let blind_com = msgs.iter().fold(one_g2, |sum, m| sum.add(m.blind_commitment));

    let pp = MTSUniversePublicParams { evals: evals_0, blinded_evals: evals_1 };
    let vk = MTSUniverseVerificationKey { vk_0: pk, vk_1: blind_com };

    (pp, vk)
}

pub fn sign(
    universe: &Universe,
    id: PartyId,
    secret: &Scalar,
    num_pubkeys: usize,
    msg: &[u8]) -> MTSPartialSignature {

    let h_m = utils::hash_to_g2(msg);

    let mut sigs: Vec<G2Projective> = Vec::new();
    for i in 0..num_pubkeys {
        //TODO: maybe better to make this PRG? Need to analyze security here.
        let sk_i = secret + Scalar::from(i as u64);
        sigs.push(h_m.mul(sk_i))
    }
    MTSPartialSignature { signer_id: id, sig_elements: sigs }
}

pub fn aggregate(
    universe: &Universe,
    pp: &MTSUniversePublicParams,
    partial_sigs: &[MTSPartialSignature]) -> Option<MTSFullSignature> {
    let t = universe.get_threshold();
    let par_xs_ranges = sig_utils::compute_universe_private_xs_ranges(universe);

    let mut all_sigs: BTreeMap<XCoord, G2Projective> = BTreeMap::new();
    for partial_sig in partial_sigs.iter() {
        let (lo,_) = par_xs_ranges.get(partial_sig.signer_id).unwrap();
        let party_weight = universe.get_weight(partial_sig.signer_id);

        for (i,sig_i) in partial_sig.sig_elements.iter().enumerate() {
            if (i < party_weight) {
                all_sigs.insert((lo + i).clone(), sig_i.clone());
            }
        }
    }

    if all_sigs.len() < t {
        return None;
    }

    let mut all_xs: Vec<Scalar> = all_sigs.
        keys().
        into_iter().
        take(t).
        into_iter().
        map(|x| Scalar::from(*x as u64)).
        collect();
}
