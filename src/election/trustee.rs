use serde::Deserialize;

mod coefficient;

use crate::election::hash::Hash;
use crate::election::parameters::Parameters;

#[derive(Deserialize)]
/// A trustee's committment to their published information, ie. their
/// public key committment and their polynomial coefficient
/// committments. This includes the non-interactive zero-knowledge
/// Schnorr proofs of posession of teh corresponding private keys and
/// coefficients. We treat the private/public key as simply the 0th
/// coefficient, and therefore we simply have `k`
/// `coefficient::Committment`s.
pub struct Committment(Vec<coefficient::Committment>);

#[derive(Debug, Clone)]
pub struct Error {
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
