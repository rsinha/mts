pub mod sig_utils {
    use crate::*;
    use ff::*;
    use crate::kzg::*;
    use crate::polynomial::*;
    use crate::universe::*;
    use std::collections::{BTreeMap};
    use rand::{Rng, rngs::ThreadRng};
    use bls12_381::{Scalar};

    pub fn sample_random_poly(
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

    /// constructs a mapping from party id to private ranges
    pub fn compute_universe_private_xs_ranges(universe: &Universe) ->
        BTreeMap<PartyId, (XCoord, XCoord)> {
        let mut mapping = BTreeMap::new();
        let mut consumed_weight: usize = 0;

        for party in universe.get_parties_in_canonical_ordering().iter() {
            let party_weight = universe.get_weight(party);

            let lo = consumed_weight + 1;
            let hi = consumed_weight + party_weight;
            mapping.insert(*party, (lo, hi));

            consumed_weight += party_weight;
        }
        mapping
    }

    pub fn compute_universe_public_xs(universe: &Universe) -> Vec<Scalar> {
        let lo = universe.get_total_weight() + 1;
        let hi = 2*universe.get_total_weight() - universe.get_threshold();

        let xs: Vec<XCoord> = (lo..hi+1).collect();

        xs.iter().map(|&x| Scalar::from(x as u64)).collect()
    }

    /// constructs a sequence of all public keys in a universe
    pub fn compute_universe_pub_keys(universe: &Universe) ->
        Vec<G1Projective> {
        let mut pubkeys = Vec::new();

        for party in universe.get_parties_in_canonical_ordering().iter() {
            for party_key in universe.get_pub_keys(party).iter() {
                pubkeys.push(party_key.clone());
            }
        }
        pubkeys
    }
}
