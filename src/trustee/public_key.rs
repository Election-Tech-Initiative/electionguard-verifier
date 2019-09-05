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

use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::schnorr;
use crate::crypto::elgamal::Group;
use crate::crypto::hash::hash_uuu;

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    /// An ElGamal public key.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    public_key: BigUint,

    /// A proof of posession of the private key.
    proof: schnorr::Proof,
}

#[derive(Debug, Serialize)]
pub struct Status {
    proof: schnorr::Status,
}

impl PublicKey {
    pub fn check(&self, group: &Group, extended_base_hash: &BigUint) -> Status {
        Status {
            proof: self.proof.check(
                group,
                &self.public_key,
                |key, comm| hash_uuu(extended_base_hash, key, comm),
            ),
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.proof.is_ok()
    }
}
