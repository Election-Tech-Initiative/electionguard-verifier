use num::BigUint;
use serde::{Deserialize, Serialize};

use super::elgamal::Group;

/// A proof of posession of the private key.
///
/// A non-interactive zero-knowledge proof of knowledge of a private
/// key `s` corresponding to a public key `h`.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// The one-use public key `k = gʳ` generated from the random
    /// one-use private key `r`. This acts as a committment to `r`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub committment: BigUint,

    /// The challenge `c` that is produced by hashing relevent
    /// parameters, including the original public key `h` and the
    /// one-time public key `k`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub challenge: BigUint,

    /// The response `u = r + c s mod (p - 1)` to the challenge, where
    /// `r` is the one-time private key corresponding to the one-time
    /// public key `k`, and `s` is the private-key corresponding to
    /// the original public key `h`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub response: BigUint,
}

impl Proof {
    #[allow(clippy::many_single_char_names)]
    pub fn verify_response(&self, group: &Group, public_key: &BigUint) -> bool {
        let Group {
            generator: g,
            prime: p,
        } = group;
        let Proof {
            committment: k,
            challenge: c,
            response: u,
        } = self;
        let h = public_key;

        BigUint::modpow(g, u, p) == (k * BigUint::modpow(h, c, p)) % p
    }
}
