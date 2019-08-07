use digest::Digest;
use num::bigint::BigUint;
use serde::Deserialize;
use sha2::Sha256;

use crate::election::hash::Hash;
use crate::election::parameters::Parameters;

/// The values an election trustee commits to as part of the
/// non-interactive zero-knowledge Schnorr proof of possession of the
/// associated private key
// We use the same type for both KeyCommittments and
// PolynomialComittments, so we have to include the key names for
// both in all the fields.
#[derive(Debug, Clone, Deserialize)]
pub struct Committment {
    /// The trustee's ElGamal public key or coefficient, `Kᵢⱼ`
    #[serde(rename = "Ki")]
    #[serde(alias = "Kij")]
    public_key: BigUint,

    /// The hash input `hᵢⱼ`
    #[serde(rename = "hi")]
    #[serde(alias = "hij")]
    hash_input: BigUint,

    /// The hash output `cᵢⱼ`
    #[serde(rename = "ci")]
    #[serde(alias = "cij")]
    hash_output: Hash,

    /// TODO maybe the challenge `uᵢⱼ`
    #[serde(rename = "ui")]
    #[serde(alias = "uij")]
    challenge: BigUint,
}

#[derive(Debug, Clone)]
pub enum Error {
    /// Signifies that the equation `cᵢⱼ = H(Q, Kᵢⱼ, hᵢⱼ)` failed to
    /// hold
    HashMismatch { lhs: Hash, rhs: Hash },
    /// Signifies that the equation `g^uᵢⱼ ≡ hᵢⱼ * Kᵢⱼ^cᵢⱼ (mod p)`
    /// failed to hold
    ModExpMismatch { lhs: BigUint, rhs: BigUint },
}

impl Committment {
    pub fn verify(self: &Self, params: &Parameters, base_hash: &Hash) -> Vec<Error> {
        // Unpack all the parameters and give them mathematical names
        let q = base_hash;

        let Committment {
            public_key: k,
            hash_input: h,
            hash_output: c,
            challenge: u,
        } = self;

        let Parameters {
            prime: p,
            generator: g,
            ..
        } = params;

        // Allocate space for the errors
        let mut errors = Vec::with_capacity(2);

        // Check that the hash equation `cᵢⱼ = H(Q, Kᵢⱼ, hᵢⱼ)` holds
        {
            let rhs = hash_eq(q, k, h);
            if &rhs != c {
                errors.push(Error::HashMismatch {
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
                errors.push(Error::ModExpMismatch { lhs, rhs });
            }
        }

        errors
    }
}

/// Compute the hash that the trustee computed in order to form the
/// non-interactive zero-knowledge Schorr proof of posession of the
/// private key, ie. `H(Q, Kᵢⱼ, hᵢⱼ)`
fn hash_eq(base_hash: &[u8], public_key: &BigUint, hash_input: &BigUint) -> [u8; 32] {
    let hasher = Sha256::new();
    let hasher = hasher.chain(base_hash);
    let hasher = hasher.chain(public_key.to_bytes_be());
    let hasher = hasher.chain(hash_input.to_bytes_be());
    hasher.result().into()
}
