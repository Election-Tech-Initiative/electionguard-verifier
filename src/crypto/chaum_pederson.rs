use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{Group, Message};
use crate::mod_arith2::*;

pub mod disj;

/// A proof transcript from the Chaum-Pedersen protocol.
///
/// We use the Chaum-Pedersen protocol to prove four kinds of properties:
///
/// * `zero`: An `elgamal::Message` is an encryption of zero.
/// * `equal`: Two `elgamal::Message`s are encryptions of the same value.
/// * `plaintext`: An `elgamal::Message` is an encryption of a particular plaintext value.
/// * `exp`: Check that a `value` is some `base` raised to the prover's private key.
///
/// If the transcript is valid for the property, and the challenge matches the expected value, then
/// the property holds.
///
/// For each of these properties, the `Proof` API provides four methods:
///
/// * `check_*`: Check that this is a valid proof of the property.  This includes checking that the
///   challenge is correct.
/// * `transcript_*`: Check only that this is a valid proof transcript for the property.
///   **This is not sufficient to prove that the property holds:** for that, the caller must also
///   check that the transcript uses the correct challenge.
/// * `prove_*`: Construct a `Proof` showing that the property holds.  (If the property doesn't
///   actually hold, this method will succeed but produce an invalid proof.)
/// * `simulate_*`: Construct a fake `Proof` using a preselected challenge.  The resulting proof
///   will pass the `transcript` check, but will fail `check` due to having the wrong challenge.
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub committment: Message,
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub challenge: BigUint,
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub response: BigUint,
}

/// The result of checking proof validity.
#[derive(Debug, Serialize)]
pub struct Status {
    pub challenge: bool,
    pub response: ResponseStatus,
}

/// The result of checking transcript validity.
/// TODO: rename this to TranscriptStatus
#[derive(Debug, Serialize)]
pub struct ResponseStatus {
    pub public_key: bool,
    pub ciphertext: bool,
}

impl Proof {
    /// Use this `Proof` to establish that `message` is an encryption of zero under `public_key`.
    pub fn check_zero(
        &self,
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Status {
        let challenge_ok = self.challenge == gen_challenge(message, &self.committment);
        let response_status = self.transcript_zero(
            group,
            public_key,
            message,
        );
        Status {
            challenge: challenge_ok,
            response: response_status,
        }
    }

    /// Check validity of this transcript for proving that `message` is an encryption of zero.
    pub fn transcript_zero(
        &self,
        group: &Group,
        public_key: &BigUint,
        message: &Message,
    ) -> ResponseStatus {
        // Unpack inputs, using the names from the crypto documentation.
        let p = &group.prime;
        let g = &group.generator;
        let h = public_key;
        let a = &message.public_key;
        let b = &message.ciphertext;
        let alpha = &self.committment.public_key;
        let beta = &self.committment.ciphertext;
        let c = &self.challenge;
        let u = &self.response;

        // "The verifier accepts if g^u = α ⋅ a^c, like they would for a Schnorr proof, but they
        // also check that h^u = β ⋅ b^c."
        let alpha_ok = g.modpow(u, p) == alpha * a.modpow(c, p) % p;
        let beta_ok = h.modpow(u, p) == beta * b.modpow(c, p) % p;

        ResponseStatus {
            public_key: alpha_ok,
            ciphertext: beta_ok,
        }
    }

    /// Construct a proof that `message` is an encryption of zero.  This requires knowing the
    /// `one_time_secret` key that was used to construct `message`.  The callback `gen_challenge`
    /// is used to generate a challenge given the message and commitment.
    pub fn prove_zero(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Proof {
        let p = &group.prime;
        let g = &group.generator;
        let h = public_key;
        let r = one_time_secret;
        let t = one_time_exponent;

        // "we publish the pair (α, β) = (g^t, h^t)."
        let alpha = g.modpow(t, p);
        let beta = h.modpow(t, p);

        let commitment = Message {
            public_key: alpha,
            ciphertext: beta,
        };
        let challenge = gen_challenge(message, &commitment);

        let c = &challenge;
        // "We response with u = t + cr like we would if this were a Schnorr proof for posession of
        // r."
        // (From the Schnorr proof section, which uses different notation:) "The prover responds to
        // the challenge with u = r + cs (mod p - 1), where s is the secret key they're trying to
        // show that they know."
        let u = (t + c * r) % &(p - 1_u8);

        Proof {
            committment: commitment,
            challenge: challenge,
            response: u,
        }
    }

    /// A "simulator" for the Chaum-Pedersen protocol.  Given a preselected `challenge` and
    /// `response`, it constructs a valid-seeming proof that `message` is an encryption of zero,
    /// regardless of the actual value of `message`.
    pub fn simulate_zero(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        challenge: &BigUint,
        response: &BigUint,
    ) -> Proof {
        let p = &group.prime;
        let g = &group.generator;
        let h = public_key;
        let a = &message.public_key;
        let b = &message.ciphertext;
        let c = challenge;
        let u = response;

        // Our goal is to compute alpha and beta such that:
        //      g.modpow(u, p) == alpha * a.modpow(c, p) % p;
        //      h.modpow(u, p) == beta * b.modpow(c, p) % p;
        // (From `check_zero`.)

        let alpha = g.modpow(u, p) * mod_inv(&a.modpow(c, p), p) % p;
        let beta = h.modpow(u, p) * mod_inv(&b.modpow(c, p), p) % p;

        Proof {
            committment: Message {
                public_key: alpha,
                ciphertext: beta,
            },
            challenge: c.clone(),
            response: u.clone(),
        }
    }


    /// Use this `Proof` to establish that `message1` is equal to `message2`.
    pub fn check_equal(
        &self,
        group: &Group,
        public_key: &BigUint,
        message1: &Message,
        message2: &Message,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Status {
        // Check that the decryptions of `message1` and `message2` are equal by proving that their
        // difference is zero.
        let combined_message = message1.h_sub(message2, group);
        self.check_zero(group, public_key, &combined_message, gen_challenge)
    }

    /// Check validity of this transcript for proving that `message1` is equal to `message2`.
    pub fn transcript_equal(
        &self,
        group: &Group,
        public_key: &BigUint,
        message1: &Message,
        message2: &Message,
    ) -> ResponseStatus {
        // Check that the decryptions of `message1` and `message2` are equal by proving that their
        // difference is zero.
        let combined_message = message1.h_sub(message2, group);
        self.transcript_zero(group, public_key, &combined_message)
    }

    /// Construct a proof that `message1` and `message2` are encryptions of the same value.
    pub fn prove_equal(
        group: &Group,
        public_key: &BigUint,
        message1: &Message,
        one_time_secret1: &BigUint,
        message2: &Message,
        one_time_secret2: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Proof {
        let p = &group.prime;

        // Check that the decryptions of `message1` and `message2` are equal by proving that their
        // difference is zero.
        let combined_message = message1.h_sub(message2, group);

        // Combining messages also combines their one-time secret keys in the same way.
        let combined_one_time_secret = mod_sub(one_time_secret1, one_time_secret2, &(p - 1_u8));

        Self::prove_zero(
            group,
            public_key,
            &combined_message,
            &combined_one_time_secret,
            one_time_exponent,
            gen_challenge,
        )
    }

    /// A "simulator" for the Chaum-Pedersen protocol.  Given a preselected `challenge` and
    /// `response`, it constructs a valid-seeming proof that `message1` and `message2` are
    /// encryptions of the same value, regardless of the actual values of `message1` and
    /// `message2`.
    pub fn simulate_equal(
        group: &Group,
        public_key: &BigUint,
        message1: &Message,
        message2: &Message,
        challenge: &BigUint,
        response: &BigUint,
    ) -> Proof {
        let combined_message = message1.h_sub(message2, group);
        Self::simulate_zero(
            group,
            public_key,
            &combined_message,
            challenge,
            response,
        )
    }


    /// Use this `Proof` to establish that `message` is an encryption of `plaintext`.
    pub fn check_plaintext(
        &self,
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        plaintext: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Status {
        // Check that `message` is equal to an encryption of `plaintext`.  Since we aren't trying
        // to hide the value of `plaintext`, the value of the one-time "secret" doesn't matter - it
        // only needs to match the secret used to construct the proof (`prove_plaintext`), so that
        // the `encrypted_plaintext` is equal in both places.
        let plaintext_one_time_secret = 0_u8.into();
        let encrypted_plaintext = Message::encrypt(
            group,
            public_key,
            plaintext,
            &plaintext_one_time_secret,
        );
        self.check_equal(group, public_key, message, &encrypted_plaintext, gen_challenge)
    }

    /// Check validity of this transcript for proving that `message` is an encryption of
    /// `plaintext`.
    pub fn transcript_plaintext(
        &self,
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        plaintext: &BigUint,
    ) -> ResponseStatus {
        // Check that `message` is equal to an encryption of `plaintext`.  Since we aren't trying
        // to hide the value of `plaintext`, the value of the one-time "secret" doesn't matter - it
        // only needs to match the secret used to construct the proof (`prove_plaintext`), so that
        // the `encrypted_plaintext` is equal in both places.
        let plaintext_one_time_secret = 0_u8.into();
        let encrypted_plaintext = Message::encrypt(
            group,
            public_key,
            plaintext,
            &plaintext_one_time_secret,
        );
        self.transcript_equal(group, public_key, message, &encrypted_plaintext)
    }

    /// Construct a proof that `message` is an encryption of `plaintext`.
    pub fn prove_plaintext(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        plaintext: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Proof {
        // This must match the `plaintext_one_time_secret` in `check_plaintext`.
        let plaintext_one_time_secret = 0_u8.into();
        let encrypted_plaintext = Message::encrypt(
            group,
            public_key,
            plaintext,
            &plaintext_one_time_secret,
        );
        Self::prove_equal(
            group,
            public_key,
            message,
            one_time_secret,
            &encrypted_plaintext,
            &plaintext_one_time_secret,
            one_time_exponent,
            gen_challenge,
        )
    }

    /// A "simulator" for the Chaum-Pedersen protocol.  Given a preselected `challenge` and
    /// `response`, it constructs a valid-seeming proof that `message` is an encryption of
    /// `plaintext`, regardless of the actual values of `message` and `plaintext`.
    pub fn simulate_plaintext(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        plaintext: &BigUint,
        challenge: &BigUint,
        response: &BigUint,
    ) -> Proof {
        // This must match the `plaintext_one_time_secret` in `check_plaintext`.
        let plaintext_one_time_secret = 0_u8.into();
        let encrypted_plaintext = Message::encrypt(
            group,
            public_key,
            plaintext,
            &plaintext_one_time_secret,
        );
        Self::simulate_equal(
            group,
            public_key,
            message,
            &encrypted_plaintext,
            challenge,
            response,
        )
    }


    /// Use this `Proof` to establish that `result = base^secret_key`, where `secret_key` is the
    /// secret key corresponding to `public_key`.
    pub fn check_exp(
        &self,
        group: &Group,
        public_key: &BigUint,
        base: &BigUint,
        result: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Status {
        // See `transcript_exp` for explanation.
        self.check_zero(
            group,
            base,
            &Message {
                public_key: public_key.clone(),
                ciphertext: result.clone(),
            },
            gen_challenge,
        )
    }

    /// Check validity of this transcript for proving that `result = base^secret_key`, where
    /// `secret_key` is the secret key corresponding to `public_key`.
    pub fn transcript_exp(
        &self,
        group: &Group,
        public_key: &BigUint,
        base: &BigUint,
        result: &BigUint,
    ) -> ResponseStatus {
        // From the ElectionGuard spec:
        //
        // "trustee Ti computes its share of the decryption as Mi=A^si mod p."
        // "commits to the pair ai,bi = g^ui mod p, A^ui mod p"
        // "verified by checking that both g^vi mod p=ai*Ki^ci mod p and A^vi mod p=bi*Mi^ci mod p"
        //
        // (Notation: their commitment (ai, bi) is our (alpha, beta); their randomness `ui` is our
        // `r`; their response `vi` is our `u`; their keypair (si, Ki) is our (s, h).
        //
        // Comparing this to `prove_zero` and `transcript_zero`, this turns out to be the same as a
        // proof that the message (Ki, Mi) / (h, result) is an encryption of zero under key `A` /
        // `base`.
        //
        // Or, looking at it another way, a proof that a message (a,b) is an encryption of zero
        // under (s, h) is the same as proving that `b = a^s`.

        self.transcript_zero(
            group,
            base,
            &Message {
                public_key: public_key.clone(),
                ciphertext: result.clone(),
            },
        )
    }

    /// Construct a proof that `result = base^secret_key`, where `secret_key` is the secret key
    /// corresponding to `public_key`.
    pub fn prove_exp(
        group: &Group,
        public_key: &BigUint,
        secret_key: &BigUint,
        base: &BigUint,
        result: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> Proof {
        // See `transcript_exp` for explanation.  In that formulation, it turns out the long-term
        // secret key is the equivalent of the "one-time secret" used to encrypt the zero message.
        Self::prove_zero(
            group,
            base,
            &Message {
                public_key: public_key.clone(),
                ciphertext: result.clone(),
            },
            secret_key,
            one_time_exponent,
            gen_challenge,
        )
    }

    /// A "simulator" for the Chaum-Pedersen protocol.  Given a preselected `challenge` and
    /// `response`, it constructs a valid-seeming proof that `result = base^secret_key`, where
    /// `secret_key` is the secret key corresponding to `public_key`.
    pub fn simulate_exp(
        group: &Group,
        public_key: &BigUint,
        base: &BigUint,
        result: &BigUint,
        challenge: &BigUint,
        response: &BigUint,
    ) -> Proof {
        // See `transcript_exp` for explanation.
        Self::simulate_zero(
            group,
            base,
            &Message {
                public_key: public_key.clone(),
                ciphertext: result.clone(),
            },
            challenge,
            response,
        )
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.challenge && self.response.is_ok()
    }
}

impl ResponseStatus {
    pub fn is_ok(&self) -> bool {
        self.public_key && self.ciphertext
    }
}


#[cfg(test)]
mod test {
    use num::BigUint;
    use crate::crypto::elgamal::{self, Message};
    use crate::crypto::hash::hash_umc;
    use super::Proof;

    /// Encrypt a zero, construct a Chaum-Pederson proof that it's zero, and check the proof.
    #[test]
    fn prove_check_zero() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = 2140_u32.into();
        let message = Message::encrypt(&group, &public_key, &0_u8.into(), &one_time_secret);
        let one_time_exponent = 3048_u32.into();
        let proof = Proof::prove_zero(
            &group,
            &public_key,
            &message,
            &one_time_secret,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_zero(
            &group,
            &public_key,
            &message,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt a nonzero value, construct a Chaum-Pederson proof claiming it's zero, and check the
    /// proof (which should fail).
    #[test]
    #[should_panic]
    fn prove_check_zero_fail() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = 2140_u32.into();
        let message = Message::encrypt(&group, &public_key, &1_u8.into(), &one_time_secret);
        let one_time_exponent = 3048_u32.into();
        let proof = Proof::prove_zero(
            &group,
            &public_key,
            &message,
            &one_time_secret,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_zero(
            &group,
            &public_key,
            &message,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// This is `prove_check_zero`, but using the largest possible nonce for the message encryption.
    /// This lets us check that we have the right modulus (p vs. p - 1) in certain places.
    #[test]
    fn prove_check_zero_extreme_nonce() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = &group.prime - 2_u8;
        let message = Message::encrypt(&group, &public_key, &0_u8.into(), &one_time_secret);
        let one_time_exponent = 3048_u32.into();
        let proof = Proof::prove_zero(
            &group,
            &public_key,
            &message,
            &one_time_secret,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_zero(
            &group,
            &public_key,
            &message,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt the same value twice, construct a Chaum-Pederson proof that they're equal, and check
    /// the proof.
    #[test]
    fn prove_check_equal() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let value = 30712_u32.into();
        let one_time_secret1 = 20147_u32.into();
        let message1 = Message::encrypt(&group, &public_key, &value, &one_time_secret1);
        let one_time_secret2 = 7494_u32.into();
        let message2 = Message::encrypt(&group, &public_key, &value, &one_time_secret2);
        let one_time_exponent = 9195_u32.into();

        let proof = Proof::prove_equal(
            &group,
            &public_key,
            &message1,
            &one_time_secret1,
            &message2,
            &one_time_secret2,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_equal(
            &group,
            &public_key,
            &message1,
            &message2,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt two different values, construct a Chaum-Pederson proof that claims they're equal, and
    /// check the proof (which should fail).
    #[test]
    #[should_panic]
    fn prove_check_equal_fail() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let value1 = 30712_u32.into();
        let one_time_secret1 = 20147_u32.into();
        let message1 = Message::encrypt(&group, &public_key, &value1, &one_time_secret1);
        let value2 = 2471_u32.into();
        let one_time_secret2 = 7494_u32.into();
        let message2 = Message::encrypt(&group, &public_key, &value2, &one_time_secret2);
        let one_time_exponent = 9195_u32.into();

        let proof = Proof::prove_equal(
            &group,
            &public_key,
            &message1,
            &one_time_secret1,
            &message2,
            &one_time_secret2,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_equal(
            &group,
            &public_key,
            &message1,
            &message2,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// This is `prove_check_equal`, but using the largest possible nonce for one of the encryptions.
    /// This lets us check that we have the right modulus (p vs. p - 1) in certain places.
    #[test]
    fn prove_check_equal_extreme_nonce() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let value = 30712_u32.into();
        let one_time_secret1 = 7494_u32.into();
        let message1 = Message::encrypt(&group, &public_key, &value, &one_time_secret1);
        let one_time_secret2 = &group.prime - 2_u8;
        let message2 = Message::encrypt(&group, &public_key, &value, &one_time_secret2);
        let one_time_exponent = 9195_u32.into();

        let proof = Proof::prove_equal(
            &group,
            &public_key,
            &message1,
            &one_time_secret1,
            &message2,
            &one_time_secret2,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_equal(
            &group,
            &public_key,
            &message1,
            &message2,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }


    /// Encrypt a value, construct a Chaum-Pederson proof that it's that value, and check the proof.
    #[test]
    fn prove_check_plaintext() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let value = 11935_u32.into();
        let one_time_secret = 13797_u32.into();
        let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
        let one_time_exponent = 30612_u32.into();
        let proof = Proof::prove_plaintext(
            &group,
            &public_key,
            &message,
            &one_time_secret,
            &value,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_plaintext(
            &group,
            &public_key,
            &message,
            &value,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt a value, construct a Chaum-Pederson proof claiming it's a different value, and check
    /// the proof (which should fail).
    #[test]
    #[should_panic]
    fn prove_check_plaintext_fail() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let value = 11935_u32.into();
        let other_value = 1609_u32.into();
        let one_time_secret = 13797_u32.into();
        let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
        let one_time_exponent = 30612_u32.into();
        let proof = Proof::prove_plaintext(
            &group,
            &public_key,
            &message,
            &one_time_secret,
            &other_value,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_plaintext(
            &group,
            &public_key,
            &message,
            &other_value,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// This is `prove_check_plaintext`, but using the largest possible nonce for the message
    /// encryption.  This lets us check that we have the right modulus (p vs. p - 1) in certain places.
    #[test]
    fn prove_check_plaintext_extreme_nonce() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let value = 11935_u32.into();
        let one_time_secret = &group.prime - 2_u8;
        let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
        let one_time_exponent = 30612_u32.into();
        let proof = Proof::prove_plaintext(
            &group,
            &public_key,
            &message,
            &one_time_secret,
            &value,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_plaintext(
            &group,
            &public_key,
            &message,
            &value,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }


    /// Generate a key pair, raise a value to the secret key, construct a Chaum-Pederson proof the
    /// exponentiation was done correctly, and check the proof.
    #[test]
    fn prove_check_exp() {
        let group = elgamal::test::group();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let secret_key = 22757_u32.into();
        let public_key = group.public_key(&secret_key);

        let base: BigUint = 1033_u32.into();
        let result = base.modpow(&secret_key, &group.prime);
        let one_time_exponent = 26480_u32.into();
        let proof = Proof::prove_exp(
            &group,
            &public_key,
            &secret_key,
            &base,
            &result,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_exp(
            &group,
            &public_key,
            &base,
            &result,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Generate a key pair, raise a value to some other exponent, construct an invalid
    /// Chaum-Pederson proof claiming that the exponentiation was done correctly, and check the
    /// proof.
    #[test]
    #[should_panic]
    fn prove_check_exp_fail() {
        let group = elgamal::test::group();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let secret_key = 22757_u32.into();
        let public_key = group.public_key(&secret_key);
        let other_exponent = 19315_u32.into();

        let base: BigUint = 1033_u32.into();
        let result = base.modpow(&other_exponent, &group.prime);
        let one_time_exponent = 26480_u32.into();
        let proof = Proof::prove_exp(
            &group,
            &public_key,
            &secret_key,
            &base,
            &result,
            &one_time_exponent,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );

        let status = proof.check_exp(
            &group,
            &public_key,
            &base,
            &result,
            |msg, comm| hash_umc(&extended_base_hash, msg, comm),
        );
        dbg!(&status);
        assert!(status.is_ok());
    }


    /// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
    /// and check the proof (which should pass).
    #[test]
    fn simulate_transcript_zero() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();

        let value = 16351_u32.into();
        let one_time_secret = 18328_u32.into();
        let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
        let challenge = 11947_u32.into();
        let response = 30170_u32.into();
        let proof = Proof::simulate_zero(
            &group,
            &public_key,
            &message,
            &challenge,
            &response,
        );

        let status = proof.transcript_zero(
            &group,
            &public_key,
            &message,
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
    /// and check the proof (which should pass).
    #[test]
    fn simulate_transcript_equal() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();

        let value1 = 16941_u32.into();
        let one_time_secret1 = 14409_u32.into();
        let message1 = Message::encrypt(&group, &public_key, &value1, &one_time_secret1);
        let value2 = 20440_u32.into();
        let one_time_secret2 = 15529_u32.into();
        let message2 = Message::encrypt(&group, &public_key, &value2, &one_time_secret2);
        let challenge = 2563_u32.into();
        let response = 4492_u32.into();
        let proof = Proof::simulate_equal(
            &group,
            &public_key,
            &message1,
            &message2,
            &challenge,
            &response,
        );

        let status = proof.transcript_equal(
            &group,
            &public_key,
            &message1,
            &message2,
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
    /// and check the proof (which should pass).
    #[test]
    fn simulate_transcript_plaintext() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();

        let value = 15271_u32.into();
        let one_time_secret = 482_u32.into();
        let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
        let plaintext = 8049_u32.into();
        let challenge = 8508_u32.into();
        let response = 23843_u32.into();
        let proof = Proof::simulate_plaintext(
            &group,
            &public_key,
            &message,
            &plaintext,
            &challenge,
            &response,
        );

        let status = proof.transcript_plaintext(
            &group,
            &public_key,
            &message,
            &plaintext,
        );
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Construct a fake proof that `result` is `base` raised to a secret key, and check the proof
    /// (which should pass).
    #[test]
    fn simulate_transcript_exp() {
        let group = elgamal::test::group();

        let public_key = 31195_u32.into();
        let other_exponent = 19315_u32.into();

        let base: BigUint = 1033_u32.into();
        let result = base.modpow(&other_exponent, &group.prime);
        let challenge = 15848_u32.into();
        let response = 12460_u32.into();
        let proof = Proof::simulate_exp(
            &group,
            &public_key,
            &base,
            &result,
            &challenge,
            &response,
        );

        let status = proof.transcript_exp(
            &group,
            &public_key,
            &base,
            &result,
        );
        dbg!(&status);
        assert!(status.is_ok());
    }
}
