use num::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::iter;

use super::elgamal::Group;
use super::hash;

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

#[derive(Debug)]
pub enum Error {
    Challenge,
    Response,
}

#[derive(Debug, Copy, Clone)]
pub enum HashInput {
    Committment,
}

impl Proof {
    pub fn check<'a>(
        &'a self,
        group: &Group,
        public_key: &BigUint,
        spec: hash::Spec<HashInput>,
    ) -> impl Iterator<Item = Error> + 'a {
        let challenge_error = if self.is_challenge_ok(spec) {
            None
        } else {
            Some(Error::Challenge)
        };

        let response_error = if self.is_response_ok(group, public_key) {
            None
        } else {
            Some(Error::Response)
        };

        iter::empty().chain(challenge_error).chain(response_error)
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

    fn is_challenge_ok(&self, spec: hash::Spec<HashInput>) -> bool {
        let expected = spec.exec::<_, Sha256>(|x| match x {
            HashInput::Committment => &self.committment,
        });

        expected == self.challenge
    }
}
