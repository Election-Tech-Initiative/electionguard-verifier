use num::BigUint;
use serde::{Deserialize, Serialize};

use super::selection::{self, Selection};
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::Group;

/// A contests consists of a list of encrypted selections, along with
/// a proof that exactly `L` of them have been selected.
#[derive(Serialize, Deserialize)]
pub struct Contest {
    /// The maximum number of selections `L` that can be made in this
    /// contest.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    max_selections: BigUint,

    /// A proof that the sum of the selections is equal to `L`, by
    /// proving that their difference is zero.
    num_selections_proof: chaum_pederson::Proof,

    /// The encrypted selections made on the ballot.
    selections: Vec<Selection>,
}

#[derive(Debug)]
pub enum Error {
    Selection(selection::Error),
}

impl Contest {
    pub fn verify<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> impl Iterator<Item = Error> + 'a {
        self.selections
            .iter()
            .flat_map(move |sel| sel.verify(group, public_key, extended_base_hash))
            .map(|e| Error::Selection(e))
    }
}
