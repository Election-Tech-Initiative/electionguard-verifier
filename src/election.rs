use num::BigUint;
use serde::{Deserialize, Serialize};
use std::iter;

use crate::crypto::elgamal::{self, Group};
use crate::decryption;
use crate::encrypted;
use crate::trustee::{self, public_key::PublicKey};

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

#[derive(Debug)]
pub enum Error {
    TrusteeKey(u32, trustee::Error),
    Ballot(u32, encrypted::contest::Error),
}

impl Record {
    pub fn verify<'a>(&'a self) -> impl Iterator<Item = Error> + 'a {
        iter::empty()
            .chain(Self::verify_trustee_keys(
                &self.trustee_public_keys,
                &self.parameters.group,
                &self.extended_base_hash,
            ))
            .chain(self.verify_cast_ballots())
    }

    fn verify_trustee_keys<'a>(
        keys: &'a [Vec<PublicKey>],
        group: &'a Group,
        extended_base_hash: &'a BigUint,
    ) -> impl Iterator<Item = Error> + 'a {
        keys.into_iter()
            .map(move |keys| trustee::verify_keys(keys, group, extended_base_hash))
            .enumerate()
            .flat_map(|(i, errors)| errors.map(move |e| (i, e)))
            .map(|(i, e)| Error::TrusteeKey(i as u32, e))
    }

    fn verify_cast_ballots<'a>(&'a self) -> impl Iterator<Item = Error> + 'a {
        use encrypted::ballot::Ballot;

        let verify_ballot = move |ballot: &'a Ballot| {
            ballot.verify(
                &self.parameters.group,
                &self.joint_public_key,
                &self.extended_base_hash,
            )
        };

        self.cast_ballots
            .iter()
            .flat_map(verify_ballot)
            .enumerate()
            .map(|(i, e)| Error::Ballot(i as u32, e))
    }
}
