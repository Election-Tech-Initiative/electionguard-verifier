//! TODO: Add documentation explaining how public/private keys are
//! generated and how the NIZKP works

use num::bigint::BigUint;
use serde::Deserialize;

use crate::election::{Hash, Parameters};
use crate::hash_all;

/// The values an election trustee commits to as part of the
/// non-interactive zero-knowledge Schnorr proof of possession of the
/// associated private key.
// We use the same type for both KeyCommittments and
// PolynomialComittments, so we have to include the key names for
// both in all the fields.
#[derive(Debug, Clone, Deserialize)]
pub struct Committment {
    /// The trustee's ElGamal public key or coefficient, `Kᵢⱼ`.
    #[serde(rename = "Ki")]
    #[serde(alias = "Kij")]
    public_key: BigUint,

    /// The hash input `hᵢⱼ`.
    #[serde(rename = "hi")]
    #[serde(alias = "hij")]
    hash_input: BigUint,

    /// The hash output or challenge `cᵢⱼ`.
    #[serde(rename = "ci")]
    #[serde(alias = "cij")]
    challenge: Hash,

    /// The proof or response to the challenge `uᵢⱼ`.
    #[serde(rename = "ui")]
    #[serde(alias = "uij")]
    response: BigUint,
}

#[derive(Debug, Clone)]
pub enum Error {
    /// Signifies that the equation `cᵢⱼ = H(Q, Kᵢⱼ, hᵢⱼ)` failed to
    /// hold.
    Hash { lhs: Hash, rhs: Hash },
    /// Signifies that the equation `g^uᵢⱼ ≡ hᵢⱼ * Kᵢⱼ^cᵢⱼ (mod p)`
    /// failed to hold.
    ModExp { lhs: BigUint, rhs: BigUint },
}

impl Committment {
    /// Checks that
    pub fn verify(self: &Self, params: &Parameters, base_hash: &Hash) -> Vec<Error> {
        // Unpack all the parameters and give them mathematical names
        let q = base_hash;

        let Parameters {
            prime: p,
            generator: g,
            ..
        } = params;

        let Committment {
            public_key: k,
            hash_input: h,
            challenge: c,
            response: u,
        } = self;

        // Create a vector for the errors, preallocating for the
        // maximum number
        let mut errors = Vec::with_capacity(2);

        // Check that the hash equation `cᵢⱼ = H(Q, Kᵢⱼ, hᵢⱼ)` holds
        {
            let rhs = hash_all!(q, k, h);
            if c != &rhs {
                errors.push(Error::Hash {
                    lhs: c.clone(),
                    rhs,
                })
            }
        }

        // Check that the modular exponentiation equation `g^uᵢⱼ ≡ hᵢⱼ
        // * Kᵢⱼ^cᵢⱼ (mod p)` holds
        {
            let lhs = BigUint::modpow(&g, &u, &p);
            let rhs = h * BigUint::modpow(&k, &BigUint::from_bytes_be(c), &p);
            if lhs != rhs {
                errors.push(Error::ModExp { lhs, rhs });
            }
        }

        errors
    }
}
