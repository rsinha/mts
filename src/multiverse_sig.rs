use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use pairing::group::{Curve};

use ff::*;
use rand::{thread_rng};
use std::collections::{BTreeMap};
use std::ops::{Add, Mul, Neg};

use crate::polynomial::*;
use crate::kzg::*;
use crate::utils;
use crate::common::sig_utils;
use crate::{XCoord, PartyId, Weight};

pub type MultiversePartialSig = Vec<(XCoord, G2Projective)>;
pub type MultiverseParams = KZGParams;

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

#[derive(Clone)]
pub struct MultiversePublicParams {
    pub coms: Vec<G1Projective>,
    pub coms_exp_k: Vec<G1Projective>,
    pub private_shares: Vec<Scalar>,
    pub public_key_s: G1Projective,
    pub public_key_k: G2Projective,
}

//#[derive(Debug, Clone)]
pub struct MultiverseParty {
    threshold_weight: Weight,
    total_weight: Weight,
    crs: KZGParams,
    k: Scalar,
    secret_polynomial: Polynomial,
    addr_book_ranges: BTreeMap<PartyId, (XCoord, XCoord)>
}

pub struct MultiverseSig {
    sigma_prime: G2Projective,
    sigma_0: G1Projective,
    sigma_1: G1Projective
}

impl <'a> MultiverseParty {

    pub fn new(
        crs: KZGParams,
        threshold_weight: usize,
        total_weight: usize,
        addr_book: &BTreeMap<PartyId, Weight>) -> MultiverseParty {

        let mut rng = thread_rng();

        MultiverseParty {
            threshold_weight: threshold_weight,
            total_weight: total_weight,
            crs: crs,
            k: Scalar::random(&mut rng),
            secret_polynomial: sig_utils::sample_random_poly(&mut rng, total_weight - 1),
            addr_book_ranges: sig_utils::addr_book_to_private_xs_ranges(addr_book)
        }
    }

    fn generate_public_shares_commitments(&self) -> (Vec<G1Projective>, Vec<G1Projective>) {
        let xs = aggregator_xs(self.total_weight, self.threshold_weight);
        let ys: Vec<Scalar> = xs.iter().map(|x| self.secret_polynomial.eval(x)).collect();

        let coms = ys.iter().map(|y| utils::commit_in_g1(&self.crs.gs[0], y)).collect();
        let coms_k = ys.iter().map(|y| utils::commit_in_g1(&self.crs.gs[0], &self.k.mul(y))).collect();

        (coms, coms_k)
    }

    fn generate_private_shares(&self) -> Vec<Scalar> {
        let xs = signer_xs(self.total_weight, self.threshold_weight);
        xs.iter().map(|x| self.secret_polynomial.eval(x)).collect()
    }

    /// produces a single payload containing all values and proofs
    pub fn setup(&self) -> MultiversePublicParams {

        let (coms_g1, coms_k_g1) = self.generate_public_shares_commitments();
        let private_shares = self.generate_private_shares();
        let secret_key = self.secret_polynomial.eval(&Scalar::zero());
        let g1_s = utils::commit_in_g1(&self.crs.gs[0], &secret_key);
        let g2_k = utils::commit_in_g2(&self.crs.hs[0], &self.k);

        MultiversePublicParams {
            coms: coms_g1,
            coms_exp_k: coms_k_g1,
            private_shares: private_shares,
            public_key_s: g1_s,
            public_key_k: g2_k
        }
    }

    pub fn sign(&self, id: PartyId, msg: &[u8], output: &MultiversePublicParams) -> MultiversePartialSig {
        let h_m = utils::hash_to_g2(msg);

        let (lo,hi) = &self.addr_book_ranges.get(&id).unwrap();
        let xs: Vec<XCoord> = (*lo..(*hi + 1)).collect();
        let ys = &output.private_shares[*lo-1..*hi];

        xs.iter().zip(ys.iter()).map(|(x,y)| (*x, h_m.mul(y))).collect()
    }

    pub fn compute_lagrange_coeffs(&self, output: &MultiversePublicParams, partial_sigs: &[MultiversePartialSig]) -> Option<Vec<Scalar>> {
        let t = self.threshold_weight;

        let mut all_sigs: BTreeMap<XCoord, G2Projective> = BTreeMap::new();
        for partial_sig in partial_sigs.iter() {
            for (x,y) in partial_sig.iter() {
                all_sigs.insert(x.clone(), y.clone());
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

        let mut agg_xs: Vec<Scalar> = aggregator_xs(self.total_weight, self.threshold_weight);
        all_xs.append(&mut agg_xs);

        Some(Polynomial::lagrange_coefficients(all_xs.as_slice()))
    }

    pub fn aggregate_with_coeffs(&self, output: &MultiversePublicParams, partial_sigs: &[MultiversePartialSig], coeffs: &Vec<Scalar>) -> Option<MultiverseSig> {
        let t = self.threshold_weight;

        let mut all_sigs: BTreeMap<XCoord, G2Projective> = BTreeMap::new();
        for partial_sig in partial_sigs.iter() {
            for (x,y) in partial_sig.iter() {
                all_sigs.insert(x.clone(), y.clone());
            }
        }

        let signer_ys: Vec<G2Projective> = all_sigs.
            values().
            into_iter().
            take(t).
            into_iter().
            map(|y| y.clone()).
            collect();

        let sigma_prime = utils::multi_exp_g2_fast(signer_ys.as_slice(), &coeffs.as_slice()[0..t]);
        let sigma_0 = utils::multi_exp_g1_fast(output.coms.as_slice(), &coeffs.as_slice()[t..]);
        let sigma_1 = utils::multi_exp_g1_fast(output.coms_exp_k.as_slice(), &coeffs.as_slice()[t..]);

        Some(MultiverseSig {
            sigma_prime: sigma_prime,
            sigma_0: sigma_0,
            sigma_1: sigma_1
        })
    }

    pub fn aggregate(&self, output: &MultiversePublicParams, partial_sigs: &[MultiversePartialSig]) -> Option<MultiverseSig> {
        let t = self.threshold_weight;

        let mut all_sigs: BTreeMap<XCoord, G2Projective> = BTreeMap::new();
        for partial_sig in partial_sigs.iter() {
            for (x,y) in partial_sig.iter() {
                all_sigs.insert(x.clone(), y.clone());
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

        let mut agg_xs: Vec<Scalar> = aggregator_xs(self.total_weight, self.threshold_weight);
        all_xs.append(&mut agg_xs);

        let coeffs: Vec<Scalar> = Polynomial::lagrange_coefficients(all_xs.as_slice());

        let signer_ys: Vec<G2Projective> = all_sigs.
            values().
            into_iter().
            take(t).
            into_iter().
            map(|y| y.clone()).
            collect();

        let sigma_prime = utils::multi_exp_g2_fast(signer_ys.as_slice(), &coeffs.as_slice()[0..t]);
        let sigma_0 = utils::multi_exp_g1_fast(output.coms.as_slice(), &coeffs.as_slice()[t..]);
        let sigma_1 = utils::multi_exp_g1_fast(output.coms_exp_k.as_slice(), &coeffs.as_slice()[t..]);

        Some(MultiverseSig {
            sigma_prime: sigma_prime,
            sigma_0: sigma_0,
            sigma_1: sigma_1
        })
    }

    pub fn verify(&self, msg: &[u8], output: &MultiversePublicParams, sig: &MultiverseSig) -> bool {
        let h_m = utils::hash_to_g2(msg);

        let check1_lhs = pairing(&output.public_key_s.add(&sig.sigma_0.neg()).to_affine(), &h_m.to_affine());
        let check1_rhs = pairing(&self.crs.gs[0].to_affine(), &sig.sigma_prime.to_affine());

        let check2_lhs = pairing(&sig.sigma_1.to_affine(), &self.crs.hs[0].to_affine());
        let check2_rhs = pairing(&sig.sigma_0.to_affine(), &output.public_key_k.to_affine());

        check1_lhs == check1_rhs && check2_lhs == check2_rhs
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::common::sig_utils;
    use rand::{thread_rng};
    use std::time::{Duration, Instant};

    #[test]
    fn test_correctness_multiverse_sig() {

        let num_parties: usize = 200;
        let individual_weight: usize = 25;
        let threshold: f64 = 0.5;

        let total_weight = individual_weight * num_parties;
        let weight_threshold = ((total_weight as f64) * threshold) as usize;

        let mut rng = thread_rng();

        let crs = sig_utils::test_setup::<50000>(&mut rng);
        let addr_book = sig_utils::create_addr_book(num_parties, individual_weight);

        let dealer = MultiverseParty::new(crs, weight_threshold, total_weight, &addr_book);

        let output = dealer.setup();

        let msg_to_sign = "Hello Multiverse";

        //let's collect signatures from 80 out of 100 parties
        let mut partial_sigs: Vec<MultiversePartialSig> = Vec::new();
        for id in 1..num_parties {
            partial_sigs.push(dealer.sign(id, msg_to_sign.as_bytes(), &output));
        }

        let now = Instant::now();
        let aggregate_sig = dealer.aggregate(&output, &partial_sigs).unwrap();
        println!("{}", now.elapsed().as_secs());
        assert_eq!(dealer.verify(msg_to_sign.as_bytes(), &output, &aggregate_sig), true);
    }
}
