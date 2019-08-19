use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::ballot;
use crate::crypto::elgamal::Group;

use super::contest::{self, Contest};

/// An encrypted ballot, consisting of the encrypted selections for
/// each contest, their proofs of well-formedness, and information
/// about where and when the ballot was encrypted.
#[derive(Serialize, Deserialize)]
pub struct Ballot {
    ballot_info: ballot::Information,
    contests: Vec<Contest>,
}

impl Ballot {
    pub fn verify<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> impl Iterator<Item = contest::Error> + 'a {
        self.contests
            .iter()
            .flat_map(move |contest| contest.verify(group, public_key, extended_base_hash))
    }
}
