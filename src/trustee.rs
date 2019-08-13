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

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    /// A proof of posession of the private key.
    proof: schnorr::Proof,

    /// An ElGamal public key.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    public_key: BigUint,
}
