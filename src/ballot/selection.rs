//! TODO: Add documentation explaining how the NIZKP works

use num::BigUint;
use serde::Deserialize;

use crate::crypto::Hash;
use crate::election::Parameters;
use crate::hash_all;

/// The pair of values which represents a single encrypted selection:
/// either a zero or a one.
#[derive(Debug, Clone, Deserialize)]
struct EncryptedSelection {
    /// The first component of the encrypted selection `α`
    alpha: BigUint,
    /// The second component of the encrypted selection `β`
    #[serde(rename = "beta")]
    beta: BigUint,
}

/// The pair of values which the prover commits to when using the
/// Chaum-Pederson protocol to prove the selection is zero.
#[derive(Debug, Clone, Deserialize)]
struct ZeroCommittment {
    /// The first component of the committment to zero `a₀`
    #[serde(rename = "a0")]
    a: BigUint,
    /// The first component of the committment to zero `b₀`
    #[serde(rename = "b0")]
    b: BigUint,
}

/// The pair of values which the prover commits to when using the
/// Chaum-Pederson protocol to prove the selection is one.
#[derive(Debug, Clone, Deserialize)]
struct OneCommittment {
    /// The first component of the committment to zero `a₁`
    #[serde(rename = "a1")]
    a: BigUint,
    /// The first component of the committment to zero `b₁`
    #[serde(rename = "b1")]
    b: BigUint,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Committment {
    selection: EncryptedSelection,
    zero_committment: ZeroCommittment,
    one_committment: OneCommittment,
    zero_challenge: BigUint,
    one_challenge: BigUint,
    zero_response: BigUint,
    one_response: BigUint,
}

#[derive(Debug, Clone)]
pub enum Error {
    /// Signifies that the equation `c = H(Q̅, α, β, a₀, b₀, a₁, b₁)`
    /// failed to hold.
    Hash { lhs: BigUint, rhs: BigUint },
}

impl Committment {
    pub fn verify(self: &Self, params: &Parameters, extended_base_hash: &Hash) -> Vec<Error> {
        // Unpack all the parameters and give them mathematical names
        let q = extended_base_hash;

        let Parameters { prime: p, .. } = params;

        let Committment {
            selection: EncryptedSelection { alpha, beta },
            zero_committment: ZeroCommittment { a: a0, b: b0 },
            one_committment: OneCommittment { a: a1, b: b1 },
            zero_challenge: c0,
            one_challenge: c1,
            ..
        } = self;

        // Create a vector for the errors, preallocating for the
        // maximum number
        let mut errors = Vec::with_capacity(1);

        {
            let lhs: BigUint = (c0 + c1) % (p - 1u8);
            let hash: Hash = hash_all!(q, alpha, beta, a0, b0, a1, b1);
            let rhs = BigUint::from_bytes_be(&hash);
            if lhs != rhs {
                errors.push(Error::Hash { lhs, rhs })
            }
        }

        errors
    }
}
