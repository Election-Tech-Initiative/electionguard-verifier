use serde::{Deserialize, Serialize};

use crate::ballot;
use crate::crypto::{chaum_pederson, elgamal};

/// An encrypted ballot, consisting of the encrypted selections for
/// each contest, their proofs of well-formedness, and information
/// about where and when the ballot was encrypted.
#[derive(Serialize, Deserialize)]
pub struct Ballot {
    ballot_info: ballot::Information,
    contests: Vec<Contest>,
}

/// A contests consists of a list of encrypted selections, along with
/// a proof that exactly `L` of them have been selected.
#[derive(Serialize, Deserialize)]
pub struct Contest {
    /// The maximum number of selections `L` that can be made in this
    /// contest.
    max_selections: u64,

    /// A proof that the sum of the selections is equal to `L`, by
    /// proving that their difference is zero.
    num_selections_proof: chaum_pederson::Proof,

    /// The encrypted selections made on the ballot.
    selections: Vec<Selection>,
}

/// A single selection in a contest, which contains the encrypted
/// value of the selection (zero or one), as well as a zero-knowledge
/// proof that the encrypted value is either a zero or a one. Both a
/// proof that the selection is zero and a proof that the selection is
/// one are always included, but depending on the actual value of the
/// selection, one of the proofs is "faked" in a way that makes the
/// verification go through. The verifier cannot and (need not)
/// determine which proof is "real" and which is "faked", but instead
/// verifies that one of them must be real.
#[derive(Serialize, Deserialize)]
pub struct Selection {
    message: elgamal::Message,
    one_proof: chaum_pederson::Proof,
    zero_proof: chaum_pederson::Proof,
}
