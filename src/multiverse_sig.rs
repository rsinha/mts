use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use pairing::group::{Curve};

use ff::*;
use rand::{thread_rng, rngs::ThreadRng};
use std::collections::{BTreeMap};
use std::ops::{Add, Mul};

use crate::polynomial::*;
use crate::kzg::*;
use crate::utils;

pub type PartyId = usize;
pub type XCoord = usize;
pub type Weight = usize;

/// given a mapping from party id to weights, this function constructs
/// a mapping from party id to private ranges
fn addr_book_to_private_xs_ranges(
    addr_book: &BTreeMap<PartyId, Weight>) -> BTreeMap<PartyId, (XCoord, XCoord)> {
    let mut mapping = BTreeMap::new();
    let mut consumed_weight: usize = 0;

    for (&party, &weight) in addr_book.iter() {
        let lo = consumed_weight + 1;
        let hi = consumed_weight + weight;
        mapping.insert(party, (lo, hi));

        consumed_weight += weight;
    }
    mapping
}

fn aggregator_xs(total_weight: Weight, threshold: Weight) -> Vec<Scalar> {
    let lo = total_weight + 1;
    let hi = 2*total_weight - threshold;

    let xs: Vec<XCoord> = (lo..hi+1).collect();

    xs.iter().map(|&x| Scalar::from(x as u64)).collect()
}

fn signer_xs(total_weight: Weight, _threshold: Weight) -> Vec<Scalar> {
    //lo and hi are inclusiv
    let lo = 1;
    let hi = total_weight;

    //add 1 because rust isnt inclusive on the hi
    let xs: Vec<XCoord> = (lo..hi+1).collect();
    xs.iter().map(|&x| Scalar::from(x as u64)).collect()
}

/// returns a random polynomial of chosen degree
fn sample_random_poly(
    rng: &mut ThreadRng,
    degree: usize) -> Polynomial {
    //rust ranges are bounded inclusively below and exclusively above
    let xs: Vec<Scalar> = (0..(degree+1)).map(|x| Scalar::from(x as u64)).collect();
    let ys: Vec<Scalar> = xs
        .iter()
        .enumerate()
        .map(|(_,_)| Scalar::random(&mut *rng))
        .collect();

    Polynomial::lagrange_interpolation(&xs[..], &ys[..])
}

fn commit_g1(params: &KZGParams, value: &Scalar) -> G1Projective {
    params.gs[0].mul(value)
}

fn commit_g2(params: &KZGParams, value: &Scalar) -> G2Projective {
    params.hs[0].mul(value)
}

#[derive(Clone)]
pub struct MultiDKGOutput {
    pub party_id: usize,
    pub coms: Vec<G1Projective>,
    pub coms_exp_k: Vec<G1Projective>,
    pub private_shares: Vec<Scalar>,
    pub public_key_s: G1Projective,
    pub public_key_k: G2Projective,
}

//#[derive(Debug, Clone)]
pub struct MultiDKGParty {
    party_id: PartyId,
    threshold_weight: Weight,
    total_weight: Weight,
    crs: KZGParams,
    k: Scalar,
    secret_polynomial: Polynomial,
    _addr_book_ranges: BTreeMap<PartyId, (XCoord, XCoord)>
}

pub struct MultiDKGSig {
    sigma_prime: G2Projective,
    sigma_0: G1Projective,
    sigma_1: G1Projective
}

impl <'a> MultiDKGParty {

    pub fn new(
        crs: KZGParams,
        party_id: usize,
        threshold_weight: usize,
        total_weight: usize,
        addr_book: &BTreeMap<PartyId, Weight>) -> MultiDKGParty {

        let mut rng = thread_rng();

        MultiDKGParty {
            party_id: party_id,
            threshold_weight: threshold_weight,
            total_weight: total_weight,
            crs: crs,
            k: Scalar::random(&mut rng),
            secret_polynomial: sample_random_poly(&mut rng, total_weight - 1),
            _addr_book_ranges: addr_book_to_private_xs_ranges(addr_book)
        }
    }

    fn generate_public_shares_commitments(&self) -> (Vec<G1Projective>, Vec<G1Projective>) {
        let xs = aggregator_xs(self.total_weight, self.threshold_weight);
        let ys: Vec<Scalar> = xs.iter().map(|x| self.secret_polynomial.eval(x)).collect();

        let coms = ys.iter().map(|y| commit_g1(&self.crs, y)).collect();
        let coms_k = ys.iter().map(|y| commit_g1(&self.crs, &self.k.mul(y))).collect();

        (coms, coms_k)
    }

    fn generate_private_shares(&self) -> Vec<Scalar> {
        let xs = signer_xs(self.total_weight, self.threshold_weight);
        xs.iter().map(|x| self.secret_polynomial.eval(x)).collect()
    }

    /// produces a single payload containing all values and proofs
    pub fn setup(&self) -> MultiDKGOutput {

        let (coms_g1, coms_k_g1) = self.generate_public_shares_commitments();
        let private_shares = self.generate_private_shares();
        let secret_key = self.secret_polynomial.eval(&Scalar::zero());
        let g1_s = commit_g1(&self.crs, &secret_key);
        let g2_k = commit_g2(&self.crs, &self.k);

        MultiDKGOutput {
            party_id: 0,
            coms: coms_g1,
            coms_exp_k: coms_k_g1,
            private_shares: private_shares,
            public_key_s: g1_s,
            public_key_k: g2_k
        }
    }

    pub fn sign(&self, msg: &[u8], output: &MultiDKGOutput) -> Vec<G2Projective> {
        let h_m = utils::hash_to_g2(msg);
        let ys = &output.private_shares[0..self.threshold_weight];
        ys.iter().map(|y| h_m.mul(y)).collect()

    }

    pub fn aggregate(&self, output: &MultiDKGOutput, partial_sigs: &Vec<G2Projective>) -> MultiDKGSig {
        let t = self.threshold_weight;
        let xs: Vec<XCoord> = (1..t+1).collect();
        let mut xss: Vec<Scalar> = xs.iter().map(|&x| Scalar::from(x as u64)).collect();

        let mut points: Vec<Scalar> = aggregator_xs(self.total_weight, self.threshold_weight);
        xss.append(&mut points);

        let coeffs: Vec<Scalar> = Polynomial::lagrange_coefficients(xss.as_slice());

        let sigma_prime = utils::multi_exp_g2_fast(partial_sigs.as_slice(), &coeffs.as_slice()[0..t]);
        let sigma_0 = utils::multi_exp_g1_fast(output.coms.as_slice(), &coeffs.as_slice()[t..]);
        let sigma_1 = utils::multi_exp_g1_fast(output.coms_exp_k.as_slice(), &coeffs.as_slice()[t..]);

        MultiDKGSig {
            sigma_prime: sigma_prime,
            sigma_0: sigma_0,
            sigma_1: sigma_1
        }
    }

    pub fn verify(&self, msg: &[u8], output: &MultiDKGOutput, sig: &MultiDKGSig) -> bool {
        let h_m = utils::hash_to_g2(msg);

        let check1_lhs = pairing(&output.public_key_s.to_affine(), &h_m.to_affine());
        let check1_rhs_1 = pairing(&self.crs.gs[0].to_affine(), &sig.sigma_prime.to_affine(), );
        let check1_rhs_2 = pairing(&sig.sigma_0.to_affine(), &h_m.to_affine(),);
        let check1_rhs = check1_rhs_1.add(check1_rhs_2);

        let check2_lhs = pairing(&sig.sigma_1.to_affine(), &self.crs.hs[0].to_affine());
        let check2_rhs = pairing(&sig.sigma_0.to_affine(), &output.public_key_k.to_affine());

        check1_lhs == check1_rhs && check2_lhs == check2_rhs
    }
}

mod multiverse_sig_utils {
    use super::*;
    use rand::{thread_rng, Rng, rngs::ThreadRng};

    pub fn create_addr_book(num_parties: usize, k: usize) -> BTreeMap<PartyId, Weight> {
        let mut ab : BTreeMap<PartyId, Weight> = BTreeMap::new();
        for party in 1..(num_parties+1) {
            ab.insert(party, k);
        }
        ab
    }

    pub fn test_setup<const MAX_COEFFS: usize>(rng: &mut ThreadRng) -> KZGParams {
        let s: Scalar = rng.gen::<u64>().into();
        setup(s, MAX_COEFFS)
    }
}

pub mod perf {
    use super::*;
    use rand::{thread_rng, Rng, rngs::ThreadRng};
    use std::time::{Instant};

    pub fn test_performance_multisig(num_parties: usize, individual_weight: usize, threshold: f64) {

        let total_weight = individual_weight * num_parties;
        let weight_threshold = ((total_weight as f64) * threshold) as usize;

        println!("Experiment with n = {}, k = {}, W = {}, T = {}",
            num_parties, individual_weight, total_weight, weight_threshold);

        let mut rng = thread_rng();

        let crs = super::multiverse_sig_utils::test_setup::<65000>(&mut rng);
        let addr_book = super::multiverse_sig_utils::create_addr_book(num_parties, individual_weight);

        let dealer = MultiDKGParty::new(crs,
            0,
            weight_threshold,
            total_weight,
            &addr_book);

        let output = dealer.setup();

        let msg_to_sign = "Hello";

        let start = Instant::now();
        let partial_sigs = dealer.sign(msg_to_sign.as_bytes(), &output);
        let signing_duration = start.elapsed();
        let signing_duration_per_party =
            (signing_duration * (individual_weight as u32)) / (weight_threshold as u32);

        println!("Time elapsed in signing is {} shares: {:?}",
            individual_weight, signing_duration_per_party);

        let start = Instant::now();
        let aggregate_sig = dealer.aggregate(&output, &partial_sigs);
        println!("Time elapsed in aggregation is: {:?}", start.elapsed());

        let start = Instant::now();
        assert_eq!(dealer.verify(msg_to_sign.as_bytes(), &output, &aggregate_sig), true);
        println!("Time elapsed in verification is: {:?}", start.elapsed());
    }

    fn test_performance_multiverse_sig() {
        let num_parties_options : Vec<usize> = vec![100, 500, 1000];
        let individual_weight_options : Vec<usize> = vec![1, 16, 64];
        let threshold_options : Vec<f64> = vec![0.5, 0.67, 0.8];

        for &num_parties in num_parties_options.iter() {
            for &individual_weight in individual_weight_options.iter() {
                for &threshold in threshold_options.iter() {
                    println!("Experiment with n = {}, k = {}, t = {}",
                        num_parties, individual_weight, threshold);

                    test_performance_multisig(num_parties, individual_weight, threshold);
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::{thread_rng, Rng, rngs::ThreadRng};
    use std::time::{Instant};

    #[test]
    fn test_correctness_multisig() {

        let num_parties: usize = 100;
        let individual_weight: usize = 10;
        let threshold: f64 = 0.5;

        let total_weight = individual_weight * num_parties;
        let weight_threshold = ((total_weight as f64) * threshold) as usize;

        println!("Experiment with n = {}, k = {}, W = {}, T = {}",
            num_parties, individual_weight, total_weight, weight_threshold);

        let mut rng = thread_rng();

        let crs = super::multiverse_sig_utils::test_setup::<1000>(&mut rng);
        let addr_book = super::multiverse_sig_utils::create_addr_book(num_parties, individual_weight);

        let dealer = MultiDKGParty::new(crs,
            0,
            weight_threshold,
            total_weight,
            &addr_book);

        let output = dealer.setup();

        let msg_to_sign = "Hello";

        let start = Instant::now();
        let partial_sigs = dealer.sign(msg_to_sign.as_bytes(), &output);
        let signing_duration = start.elapsed();
        let signing_duration_per_party =
            (signing_duration * (individual_weight as u32)) / (weight_threshold as u32);

        println!("Time elapsed in signing is {} shares: {:?}",
            individual_weight, signing_duration_per_party);

        let start = Instant::now();
        let aggregate_sig = dealer.aggregate(&output, &partial_sigs);
        println!("Time elapsed in aggregation is: {:?}", start.elapsed());

        let start = Instant::now();
        assert_eq!(dealer.verify(msg_to_sign.as_bytes(), &output, &aggregate_sig), true);
        println!("Time elapsed in verification is: {:?}", start.elapsed());
    }
}
