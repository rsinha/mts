use std::collections::{BTreeMap};
use crate::{UniverseId, PartyId, Weight, PartyPublicKey, AddressBook};
use std::rc::Rc;
use std::fmt;

/// universe is represented by its participants and access structure
#[derive(Clone)]
pub struct Universe {
    /// contains mapping from party id to its weight and public keys
    pub address_book: AddressBook,
    /// signing threshold for this universe
    pub signing_threshold: Weight,
}

/// prints the mapping from party id to its weight
impl fmt::Display for Universe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        output.push_str(format!("universe: ").as_str());
        for (party, (weight, _)) in self.address_book.iter() {
            output.push_str(format!("({},{}) ", party, weight).as_str());
        }
        output.push_str(format!("\t threshold: {}", self.signing_threshold).as_str());
        write!(f, "{}", output)
    }
}

impl Universe {
    /// creates a new, empty universe
    pub fn new() -> Self {
        Universe {
            address_book: BTreeMap::new(),
            signing_threshold: 0
        }
    }

    //todo add error codes here
    pub fn add_party(&mut self,
        party_id: PartyId,
        weight: Weight,
        pub_keys: Rc<Vec<PartyPublicKey>>) {
        if weight <= pub_keys.as_ref().len() {
            self.address_book.insert(party_id, (weight, pub_keys.clone()));
        } else {
            //todo: return some error code.
        }
    }

    pub fn set_threshold(&mut self, t: Weight) {
        self.signing_threshold = t;
    }

    pub fn get_threshold(&self) -> Weight {
        self.signing_threshold
    }

    pub fn get_total_weight(&self) -> Weight {
        let mut aggregate_weight: Weight = 0;
        for (&_, (weight, _)) in self.address_book.iter() {
            aggregate_weight += weight;
        }
        aggregate_weight
    }

    pub fn get_unique_universe_id(&self) -> UniverseId {
        return [0; 32];
    }

    pub fn get_parties_in_canonical_ordering(&self) -> Vec<PartyId> {
        let mut parties = Vec::new();
        for (&party, (_, _)) in self.address_book.iter() {
            parties.push(party);
        }
        parties
    }

    pub fn get_pub_keys(&self, party: &PartyId) -> Rc<Vec<PartyPublicKey>> {
        //type AddressBook = BTreeMap<PartyId, (Weight, Rc<Vec<PartyPublicKey>>)>;
        let (_, keys) = self.address_book.get(party).unwrap();
        Rc::clone(keys)
    }

    pub fn get_weight(&self, party: &PartyId) -> Weight {
        //type AddressBook = BTreeMap<PartyId, (Weight, Rc<Vec<PartyPublicKey>>)>;
        let (w, _) = self.address_book.get(party).unwrap();
        *w
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::sig_utils;

    #[test]
    fn test_universe() {
        let mut universe = Universe::new();
        universe.add_party(1, 10, Rc::new(Vec::new()));
        universe.add_party(2, 10, Rc::new(Vec::new()));
        universe.add_party(3, 5, Rc::new(Vec::new()));
        universe.add_party(4, 3, Rc::new(Vec::new()));
        universe.set_threshold(10);
        println!("{}", universe);

        for (party, (lo,hi)) in
            &sig_utils::compute_universe_private_xs_ranges(&universe) {
            println!("{party}: {lo}..{hi}");
        }
    }
}
