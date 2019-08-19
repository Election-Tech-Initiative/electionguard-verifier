use digest::Digest;
use num::BigUint;
use serde::{Deserialize, Serialize};
use std::iter;

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

#[derive(Debug)]
pub enum Error {
    Challenge,
    Response,
}

impl Proof {
    pub fn verify<H, D>(
        &self,
        group: &Group,
        public_key: &BigUint,
        hasher: H,
    ) -> impl Iterator<Item = Error>
    where
        H: FnOnce(D, &[u8]) -> D,
        D: Digest,
    {
        iter::empty()
            .chain(self.verify_challenge(hasher))
            .chain(self.verify_response(group, public_key))
    }

    fn verify_challenge<H, D>(&self, hasher: H) -> Option<Error>
    where
        H: FnOnce(D, &[u8]) -> D,
        D: Digest,
    {
        let digest: D = Digest::new();
        let digest = hasher(digest, &self.committment.to_bytes_be());
        let hash = digest.result();

        if self.challenge == BigUint::from_bytes_be(hash.as_slice()) {
            None
        } else {
            Some(Error::Challenge)
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn verify_response(&self, group: &Group, public_key: &BigUint) -> Option<Error> {
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

        if BigUint::modpow(g, u, p) == (k * BigUint::modpow(h, c, p)) % p {
            None
        } else {
            Some(Error::Response)
        }
    }
}
