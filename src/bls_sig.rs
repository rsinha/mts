use bls12_381::{pairing, G1Projective, G2Projective, Scalar};
use pairing::group::{Curve};

use rand::{thread_rng};
use std::collections::{BTreeMap};
use std::ops::{Mul};

use crate::polynomial::*;
use crate::kzg::*;
use crate::utils;
use crate::common::sig_utils;
use crate::{XCoord, PartyId, Weight};

pub type BlsPartialSig = Vec<(XCoord, G2Projective)>;
pub type BlsParams = KZGParams;

fn signer_xs(total_weight: Weight, _threshold: Weight) -> Vec<Scalar> {
    //lo and hi are inclusiv
    let lo = 1;
    let hi = total_weight;

    //add 1 because rust isnt inclusive on the hi
    let xs: Vec<XCoord> = (lo..hi+1).collect();
    xs.iter().map(|&x| Scalar::from(x as u64)).collect()
}

#[derive(Clone)]
pub struct BlsPublicParams {
    pub private_shares: Vec<Scalar>,
    pub public_key_s: G1Projective,
}

//#[derive(Debug, Clone)]
pub struct BlsParty {
    threshold_weight: Weight,
    total_weight: Weight,
    crs: KZGParams,
    secret_polynomial: Polynomial,
    addr_book_ranges: BTreeMap<PartyId, (XCoord, XCoord)>
}

pub struct BlsSig {
    sigma: G2Projective
}

impl <'a> BlsParty {

    pub fn new(
        crs: KZGParams,
        threshold_weight: usize,
        total_weight: usize,
        addr_book: &BTreeMap<PartyId, Weight>) -> BlsParty {

        let mut rng = thread_rng();

        BlsParty {
            threshold_weight: threshold_weight,
            total_weight: total_weight,
            crs: crs,
            secret_polynomial: sig_utils::sample_random_poly(&mut rng, threshold_weight - 1),
            addr_book_ranges: sig_utils::addr_book_to_private_xs_ranges(addr_book)
        }
    }

    fn generate_private_shares(&self) -> Vec<Scalar> {
        let xs = signer_xs(self.total_weight, self.threshold_weight);
        xs.iter().map(|x| self.secret_polynomial.eval(x)).collect()
    }

    /// produces a single payload containing all values and proofs
    pub fn setup(&self) -> BlsPublicParams {
        let private_shares = self.generate_private_shares();
        let secret_key = self.secret_polynomial.eval(&Scalar::zero());
        let g1_s = utils::commit_in_g1(&self.crs.gs[0], &secret_key);

        BlsPublicParams {
            private_shares: private_shares,
            public_key_s: g1_s,
        }
    }

    pub fn sign(&self, id: PartyId, msg: &[u8], output: &BlsPublicParams) -> BlsPartialSig {
        let h_m = utils::hash_to_g2(msg);

        let (lo,hi) = &self.addr_book_ranges.get(&id).unwrap();
        let xs: Vec<XCoord> = (*lo..(*hi + 1)).collect();
        let ys = &output.private_shares[*lo-1..*hi];

        xs.iter().zip(ys.iter()).map(|(x,y)| (*x, h_m.mul(y))).collect()
    }

    pub fn aggregate(&self, _output: &BlsPublicParams, partial_sigs: &[BlsPartialSig]) -> Option<BlsSig> {
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

        let all_xs: Vec<Scalar> = all_sigs.
            keys().
            into_iter().
            take(t).
            into_iter().
            map(|x| Scalar::from(*x as u64)).
            collect();

        let coeffs: Vec<Scalar> = Polynomial::lagrange_coefficients(all_xs.as_slice());

        let signer_ys: Vec<G2Projective> = all_sigs.
            values().
            into_iter().
            take(t).
            into_iter().
            map(|y| y.clone()).
            collect();

        let sigma = utils::multi_exp_g2_fast(signer_ys.as_slice(), &coeffs.as_slice()[0..t]);

        Some(BlsSig { sigma: sigma })
    }

    pub fn verify(&self, msg: &[u8], output: &BlsPublicParams, sig: &BlsSig) -> bool {
        let h_m = utils::hash_to_g2(msg);

        let check_lhs = pairing(&output.public_key_s.to_affine(), &h_m.to_affine());
        let check_rhs = pairing(&self.crs.gs[0].to_affine(), &sig.sigma.to_affine());

        check_lhs == check_rhs
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::{thread_rng};

    #[test]
    fn test_correctness_bls_sig() {

        let num_parties: usize = 20;
        let individual_weight: usize = 8;
        let threshold: f64 = 0.5;

        let total_weight = individual_weight * num_parties;
        let weight_threshold = ((total_weight as f64) * threshold) as usize;

        let mut rng = thread_rng();

        let crs = sig_utils::test_setup::<200>(&mut rng);
        let addr_book = sig_utils::create_addr_book(num_parties, individual_weight);

        let dealer = BlsParty::new(crs, weight_threshold, total_weight, &addr_book);

        let output = dealer.setup();

        let msg_to_sign = "Hello Multiverse";

        let mut partial_sigs: Vec<BlsPartialSig> = Vec::new();
        for id in 1..num_parties {
            partial_sigs.push(dealer.sign(id, msg_to_sign.as_bytes(), &output));
        }

        let aggregate_sig = dealer.aggregate(&output, &partial_sigs).unwrap();
        assert_eq!(dealer.verify(msg_to_sign.as_bytes(), &output, &aggregate_sig), true);
    }
}
