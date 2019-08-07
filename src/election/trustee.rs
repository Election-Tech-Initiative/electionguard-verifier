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

use serde::Deserialize;

mod coefficient;

use crate::election::hash::Hash;
use crate::election::parameters::Parameters;

#[derive(Deserialize)]
/// A trustee's committment to their published information, consisting
/// of their `k` public key and coefficients, as well `k`
/// non-interactive zero-knowledge Schnorr proofs of posession of the
/// corresponding private key or coefficient.
pub struct Committment(Vec<coefficient::Committment>);

#[derive(Debug, Clone)]
pub struct Error {
    /// The index of the coefficient where the error occured.
    index: u32,
    error: coefficient::Error,
}

impl Committment {
    pub fn verify(self: &Self, params: &Parameters, base_hash: &Hash) -> Vec<Error> {
        self.0
            .iter()
            .flat_map(|committment| committment.verify(params, base_hash))
            .enumerate()
            .map(|(i, error)| Error {
                index: i as u32,
                error,
            })
            .collect()
    }
}
