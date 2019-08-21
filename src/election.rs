use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{self, Group};
use crate::crypto::schnorr;
use crate::decryption;
use crate::encrypted;
use crate::trustee::public_key::PublicKey;

/// All the parameters necessary to form the election.
#[derive(Serialize, Deserialize)]
pub struct Parameters {
    /// The date on which the election takes place.
    date: String,

    /// The location where the election takes place
    location: String,

    /// The number of election trustees `n`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    num_trustees: BigUint,

    /// The threshold `k` of trustees required to complete
    /// verification.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    threshold: BigUint,

    #[serde(flatten)]
    group: elgamal::Group,
}

/// All data from an ElectionGuard election
#[derive(Serialize, Deserialize)]
pub struct Record {
    /// The base hash `Q` which is a SHA-256 hash of eleciton
    /// parameters including the prime modulus, generator, number of
    /// trustees, decryption threshold value, date, and jurisdictional
    /// information, as well as the contest configurations.
    #[serde(deserialize_with = "crate::deserialize::hash")]
    base_hash: BigUint,

    /// The encrypted ballots cast in the election.
    cast_ballots: Vec<encrypted::ballot::Ballot>,

    /// The decryptions of the tallies of each option for each
    /// contests in the election.
    contest_tallies: Vec<Vec<decryption::Tally>>,

    /// The extended base hash `Q̅`.
    #[serde(deserialize_with = "crate::deserialize::hash")]
    extended_base_hash: BigUint,

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
    trustee_public_keys: Vec<Vec<PublicKey>>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    trustee_public_keys: Vec<Vec<schnorr::Status>>,
    cast_ballots: Vec<encrypted::ballot::Status>,
}

impl Record {
    pub fn check(&self) -> Status {
        Status {
            trustee_public_keys: Self::check_trustee_public_keys(
                &self.trustee_public_keys,
                &self.parameters.group,
                &self.extended_base_hash,
            ),
            cast_ballots: Self::check_cast_ballots(
                &self.cast_ballots,
                &self.parameters.group,
                &self.joint_public_key,
                &self.extended_base_hash,
            ),
        }
    }

    fn check_trustee_public_keys(
        keys: &[Vec<PublicKey>],
        group: &Group,
        extended_base_hash: &BigUint,
    ) -> Vec<Vec<schnorr::Status>> {
        keys.iter()
            .map(|keys| {
                keys.iter()
                    .map(|key| key.check(group, extended_base_hash))
                    .collect()
            })
            .collect()
    }

    fn check_cast_ballots(
        ballots: &[encrypted::ballot::Ballot],
        group: &Group,
        public_key: &BigUint,
        extended_base_hash: &BigUint,
    ) -> Vec<encrypted::ballot::Status> {
        ballots
            .iter()
            .map(|ballot| ballot.check(group, public_key, extended_base_hash))
            .collect()
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        Self::is_trustee_public_keys_ok(&self.trustee_public_keys)
            && Self::is_cast_ballots_ok(&self.cast_ballots)
    }

    fn is_trustee_public_keys_ok(keys: &[Vec<schnorr::Status>]) -> bool {
        keys.iter()
            .all(|keys| keys.iter().all(schnorr::Status::is_ok))
    }

    fn is_cast_ballots_ok(ballots: &[encrypted::ballot::Status]) -> bool {
        ballots.iter().all(encrypted::ballot::Status::is_ok)
    }
}
