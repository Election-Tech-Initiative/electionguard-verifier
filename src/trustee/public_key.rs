//! During the key ceremony, each trustee randomly generates `k`
//! coefficients, the first of which is considered their private key.
//! From this they compute `k` public coefficients, the first of which
//! is considered their public key.
//!
//! The trustee will publish their public key and coefficients. We
//! want the trustee to be able to prove to an observer that they
//! indeed do posess the corresponding private key and coefficients,
//! without revealing them. To this end, each trustee publishes a
//! non-interactive zero-knowledge Schnorr proof that functions as a
//! committment to the private values: they cannot lose or alter their
//! private keys and coefficients without invalidating the proofs that
//! they have published.

use digest::Digest;
use num::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::iter;

use crate::crypto::{elgamal::Group, schnorr};

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    /// A proof of posession of the private key.
    proof: schnorr::Proof,

    /// An ElGamal public key.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    public_key: BigUint,
}

#[derive(Debug)]
pub enum Error {
    ProofChallenge,
    ProofResponse,
}

impl PublicKey {
    pub fn verify<'a>(
        &'a self,
        group: &'a Group,
        extended_base_hash: &'a BigUint,
    ) -> impl Iterator<Item = Error> + 'a {
        let challenge_error = if self.expected_challenge(extended_base_hash) == self.proof.challenge
        {
            None
        } else {
            Some(Error::ProofChallenge)
        };

        let response_error = if self.proof.verify_response(group, &self.public_key) {
            None
        } else {
            Some(Error::ProofResponse)
        };

        iter::empty().chain(challenge_error).chain(response_error)
    }

    fn expected_challenge(&self, extended_base_hash: &BigUint) -> BigUint {
        let hash = [
            extended_base_hash,
            &self.public_key,
            &self.proof.committment,
        ]
        .into_iter()
        .copied()
        .map(BigUint::to_bytes_be)
        .fold(Sha256::new(), Sha256::chain)
        .result();

        BigUint::from_bytes_be(hash.as_slice())
    }
}
