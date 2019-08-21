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

#[derive(Debug, Serialize)]
pub struct Status {
    selections: Vec<selection::Status>,
}

impl Contest {
    pub fn check<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> Status {
        Status {
            selections: self
                .selections
                .iter()
                .map(move |sel| sel.check(group, public_key, extended_base_hash))
                .collect(),
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.selections.iter().all(selection::Status::is_ok)
    }
}
