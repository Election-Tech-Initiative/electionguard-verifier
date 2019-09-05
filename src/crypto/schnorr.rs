use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::Group;
use crate::mod_arith2::*;

/// A proof of posession of the private key.
///
/// This provides the same API as `chaum_pederson::Proof`, except there is only one property to
/// reason about, so there is only one variant of `check`, `transcript`, `prove`, and `simulate`.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
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

impl Proof {
    /// Use this `Proof` to establish that the prover possesses the private key corresponding to
    /// `public_key`.
    pub fn check(
        &self,
        group: &Group,
        public_key: &BigUint,
        gen_challenge: impl FnOnce(&BigUint, &BigUint) -> BigUint,
    ) -> Status {
        let challenge_ok = self.challenge == gen_challenge(public_key, &self.committment);
        let response_ok = self.transcript(
            group,
            public_key,
        );
        Status {
            challenge: challenge_ok,
            response: response_ok,
        }
    }

    /// Check validity of this transcript for proving possession of the private key corresponding
    /// to `public_key`.
    pub fn transcript(
        &self,
        group: &Group,
        public_key: &BigUint,
    ) -> bool {
        // Unpack inputs, using the names from the crypto documentation.
        let p = &group.prime;
        let g = &group.generator;
        let h = public_key;
        let k = &self.committment;
        let c = &self.challenge;
        let u = &self.response;

        // "The verifier accepts if g^u = k ⋅ h^c"
        g.modpow(u, p) == k * h.modpow(c, p) % p
    }

    pub fn prove(
        group: &Group,
        public_key: &BigUint,
        secret_key: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&BigUint, &BigUint) -> BigUint,
    ) -> Proof {
        let p = &group.prime;
        let g = &group.generator;
        let s = secret_key;
        let r = one_time_exponent;

        // "The prover commits to that one-time private key by publishing the one-time public key
        // k = g^r."
        let k = g.modpow(r, p);

        // "The verifier gives the prover a random challenge c such that 0 < c < p - 1"
        let commitment = k;
        let challenge = gen_challenge(public_key, &commitment);
        let c = &challenge;

        // "The prover responds to the challenge with u = r + cs \bmod p - 1, where s is the secret
        // key they're trying to show that they know."
        let u = (r + c * s) % &(p - 1_u8);

        Proof {
            committment: commitment,
            challenge: challenge,
            response: u,
        }
    }

    pub fn simulate(
        group: &Group,
        public_key: &BigUint,
        challenge: &BigUint,
        response: &BigUint,
    ) -> Proof {
        let p = &group.prime;
        let g = &group.generator;
        let h = public_key;
        let c = challenge;
        let u = response;

        // Our goal is to compute k such that:
        //      g.modpow(u, p) == k * h.modpow(c, p) % p;
        // (From `check`.)

        let k = g.modpow(u, p) * mod_inv(&h.modpow(c, p), p) % p;

        Proof {
            committment: k,
            challenge: c.clone(),
            response: u.clone(),
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.challenge && self.response
    }
}


#[cfg(test)]
mod test {
    use crate::crypto::elgamal;
    use crate::crypto::hash::hash_uuu;
    use super::Proof;

    /// Generate a key pair, construct a Schnorr proof of possession of the private key, and check
    /// the proof.
    #[test]
    fn prove_check() {
        let group = elgamal::test::group();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let secret_key = 18930_u32.into();
        let public_key = group.public_key(&secret_key);
        let one_time_exponent = 26664_u32.into();
        let proof = Proof::prove(
            &group,
            &public_key,
            &secret_key,
            &one_time_exponent,
            |key, comm| hash_uuu(&extended_base_hash, key, comm),
        );

        let status = proof.check(
            &group,
            &public_key,
            |key, comm| hash_uuu(&extended_base_hash, key, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Generate a key pair, construct an invalid Schnorr proof using the wrong secret key, and
    /// check the proof (which should fail).
    #[test]
    #[should_panic]
    fn prove_check_fail() {
        let group = elgamal::test::group();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let secret_key = 18930_u32.into();
        let public_key = group.public_key(&secret_key);
        let other_secret_key = 22703_u32.into();
        let one_time_exponent = 26664_u32.into();
        let proof = Proof::prove(
            &group,
            &public_key,
            &other_secret_key,
            &one_time_exponent,
            |key, comm| hash_uuu(&extended_base_hash, key, comm),
        );

        let status = proof.check(
            &group,
            &public_key,
            |key, comm| hash_uuu(&extended_base_hash, key, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Generate a public key, construct a fake Schnorr proof using a pre-selected challenge, and
    /// check the proof transcript (which should pass).
    #[test]
    fn simulate_transcript() {
        let group = elgamal::test::group();

        let public_key = 1647_u32.into();
        let challenge = 10335_u32.into();
        let response = 14942_u32.into();
        let proof = Proof::simulate(
            &group,
            &public_key,
            &challenge,
            &response,
        );

        let status = proof.transcript(
            &group,
            &public_key,
        );
        dbg!(&status);
        assert!(status);
    }
}
