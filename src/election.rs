use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::decryption;
use crate::encrypted;
use crate::trustee;

/// All the parameters necessary to form the election.
#[derive(Serialize, Deserialize)]
pub struct Parameters {
    /// The date on which the election takes place.
    date: String,

    /// The generator `g` of the multiplicative subgroup `Z^*_q`,
    /// where `p = 2q + 1`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    generator: BigUint,

    /// The location where the election takes place
    location: String,

    /// The number of election trustees `n`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    num_trustees: BigUint,

    /// The safe prime modulus `p`
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    prime: BigUint,

    /// The threshold `k` of trustees required to complete
    /// verification.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    threshold: BigUint,
}

/// All data from an ElectionGuard election
#[derive(Serialize, Deserialize)]
pub struct Record {
    /// The base hash `Q` which is a SHA-256 hash of eleciton
    /// parameters including the prime modulus, generator, number of
    /// trustees, decryption threshold value, date, and jurisdictional
    /// information, as well as the contest configurations.
    base_hash: String,

    /// The encrypted ballots cast in the election.
    cast_ballots: Vec<encrypted::Ballot>,

    /// The decryptions of the tallies of each option for each
    /// contests in the election.
    contest_tallies: Vec<Vec<decryption::Tally>>,

    /// The extended base hash `Q̅`.
    extended_base_hash: String,

    /// The election public key `K`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    joint_public_key: BigUint,

    parameters: Parameters,

    /// The decryptions of the ballots spoiled in the election,
    /// including their encrypted selections, their decrypted
    /// selections, the cleartext of each selection, and proofs of the
    /// correctness of the decryptions.
    spoiled_ballots: Vec<decryption::Ballot>,

    /// The public keys/coefficient commitments for each trustee.
    trustee_public_keys: Vec<Vec<trustee::PublicKey>>,
}
