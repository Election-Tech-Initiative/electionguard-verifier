use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::ballot;
use crate::crypto::group::Element;

use super::contest::{self, Contest};

/// An encrypted ballot, consisting of the encrypted selections for
/// each contest, their proofs of well-formedness, and information
/// about where and when the ballot was encrypted.
#[derive(Serialize, Deserialize)]
pub struct Ballot {
    ballot_info: ballot::Information,
    contests: Vec<Contest>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    contests: Vec<contest::Status>,
}

impl Ballot {
    pub fn check(
        &self,
        public_key: &Element,
        extended_base_hash: &BigUint,
    ) -> Status {
        Status {
            contests: self.contests.iter()
                .map(move |contest| contest.check(public_key, extended_base_hash))
                .collect(),
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.contests.iter().all(contest::Status::is_ok)
    }
}
