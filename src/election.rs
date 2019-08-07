use num::bigint::BigUint;
use serde::Deserialize;

mod hash;
mod parameters;
mod trustee;

use hash::Hash;
use parameters::Parameters;

#[derive(Deserialize)]
pub struct Results {
    parameters: Parameters,

    /// The base hash which is a SHA-256 hash of parameters
    #[serde(rename = "Q")]
    base_hash: [u8; 32],

    #[serde(rename = "listOfTrusteeCommitments")]
    trustee_committments: Vec<trustee::Committment>,

    /// The election public key
    #[serde(rename = "K")]
    public_key: BigUint,

    /// The SHA-256 hash of the trustee committments, the election
    /// public key, and the base hash
    #[serde(rename = "Qbar")]
    extended_base_hash: [u8; 32],

    /// All of the encrypted ballots cast in the election
    cast_ballots: Vec<EncryptedBallot>,

    /// All of the ballots that were spoiled in the election
    spoiled_ballots: Vec<BallotDecryption>,

    /// All the tallied contests in the election
    tallies: Vec<ContestTally>,
}

#[derive(Deserialize)]
pub struct EncryptedBallot();

#[derive(Deserialize)]
pub struct BallotDecryption();

#[derive(Deserialize)]
pub struct ContestTally();

#[derive(Debug, Clone)]
pub enum Error {
    Trustee { index: u32, error: trustee::Error },
}

impl Results {
    pub fn validate(self: &Self) -> Vec<Error> {
        self.trustee_committments
            .iter()
            .flat_map(|committment| committment.verify(&self.parameters, &self.base_hash))
            .enumerate()
            .map(|(i, error)| Error::Trustee {
                index: i as u32,
                error,
            })
            .collect()
    }
}
