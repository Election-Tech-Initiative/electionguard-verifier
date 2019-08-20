use num::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::elgamal::Group;
use super::hash::Spec;

/// A proof of posession of the private key.
///
/// A non-interactive zero-knowledge proof of knowledge of a private
/// key `s` corresponding to a public key `h`.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// The one-use public key `k = gʳ` generated from the random
    /// one-use private key `r`. This acts as a committment to `r`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    committment: BigUint,

    /// The challenge `c` that is produced by hashing relevent
    /// parameters, including the original public key `h` and the
    /// one-time public key `k`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    challenge: BigUint,

    /// The response `u = r + c s mod (p - 1)` to the challenge, where
    /// `r` is the one-time private key corresponding to the one-time
    /// public key `k`, and `s` is the private-key corresponding to
    /// the original public key `h`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    response: BigUint,
}

#[derive(Debug, Serialize)]
pub struct Status {
    challenge: bool,
    response: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum HashInput {
    Committment,
}

impl Proof {
    pub fn check(&self, group: &Group, public_key: &BigUint, spec: Spec<HashInput>) -> Status {
        Status {
            challenge: self.is_challenge_ok(spec),
            response: self.is_response_ok(group, public_key),
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn is_response_ok(&self, group: &Group, public_key: &BigUint) -> bool {
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

    fn is_challenge_ok(&self, spec: Spec<HashInput>) -> bool {
        let expected = spec.exec::<_, Sha256>(|x| match x {
            HashInput::Committment => &self.committment,
        });

        expected == self.challenge
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.challenge && self.response
    }
}
