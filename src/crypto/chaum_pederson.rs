use num::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::elgamal::{Group, Message};
use crate::crypto::hash::Spec;
use crate::mod_arith2::*;

pub mod disj;

/// A proof transcript from the Chaum-Pedersen protocol.
///
/// We use the Chaum-Pedersen protocol to prove three kinds of properties:
///
/// * `zero`: An `elgamal::Message` is an encryption of zero.
/// * `equal`: Two `elgamal::Message`s are encryptions of the same value.
/// * `plaintext`: An `elgamal::Message` is an encryption of a particular plaintext value.
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

#[derive(Debug, Copy, Clone)]
pub enum HashInput {
    CommittmentPublicKey,
    CommittmentCiphertext,
}

impl Proof {
    pub fn check(
        &self,
        group: &Group,
        message: &Message,
        public_key: &BigUint,
        spec: Spec<HashInput>,
    ) -> Status {
        Status {
            challenge: self.is_challenge_ok(group, spec),
            response: self.check_response(group, message, public_key),
        }
    }

    fn is_challenge_ok(&self, group: &Group, spec: Spec<HashInput>) -> bool {
        let Group { prime: p, .. } = group;
        let expected = spec.exec::<_, Sha256>(|x| self.resolver()(x));
        expected == self.challenge
    }

    fn check_response(
        &self,
        group: &Group,
        message: &Message,
        public_key: &BigUint,
    ) -> ResponseStatus {
        ResponseStatus {
            public_key: self.is_response_public_key_ok(group, message),
            ciphertext: self.is_response_ciphertext_ok(group, message, public_key),
        }
    }

    /// Verify that the first component of the response (the one-time public key) is correct:
    /// `gᵘ = α aᶜ`.
    ///
    /// # Parameters
    /// - `group`: the ElGamal group for the message, `(p, g)`
    /// - `message`: the message we want to prove encodes zero, `(a,
    ///    b) = (gʳ, m hʳ)`, where `r` is the private key used to
    ///    encrypt the message.
    #[allow(clippy::many_single_char_names)]
    fn is_response_public_key_ok(&self, group: &Group, message: &Message) -> bool {
        let Group {
            generator: g,
            prime: p,
        } = group;
        let Proof {
            committment: Message {
                public_key: alpha, ..
            },
            challenge: c,
            response: u,
        } = self;
        let Message { public_key: a, .. } = message;

        BigUint::modpow(g, u, p) == (alpha * BigUint::modpow(a, c, p)) % p
    }

    /// Verify that the second component of the response (the ciphertext) is correct:
    /// `hᵘ = β bᶜ`.
    ///
    /// # Parameters
    /// - `group`: the ElGamal group for the message, `(p, g)`
    /// - `message`: the message we want to prove encodes zero, `(a,
    ///    b) = (gʳ, m hʳ)`, where `r` is the private key used to
    ///    encrypt the message.
    /// - `public_key`: the public key `h` used to encrypt the message
    #[allow(clippy::many_single_char_names)]
    fn is_response_ciphertext_ok(
        &self,
        group: &Group,
        message: &Message,
        public_key: &BigUint,
    ) -> bool {
        let Group { prime: p, generator: g } = group;
        let Proof {
            committment: Message {
                ciphertext: beta, ..
            },
            challenge: c,
            response: u,
        } = self;
        let Message { ciphertext: b, .. } = message;
        let h = public_key;

        //BigUint::modpow(h, u, p) == (beta * BigUint::modpow(b, c, p)) % p
        (BigUint::modpow(h, u, p) * BigUint::modpow(g, c, p)) % p
            == (beta * BigUint::modpow(b, c, p)) % p
    }

    fn resolver<'a>(&'a self) -> impl Fn(HashInput) -> &'a BigUint {
        use HashInput::*;

        move |x| match x {
            CommittmentPublicKey => &self.committment.public_key,
            CommittmentCiphertext => &self.committment.ciphertext,
        }
    }


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
        let a = &message.public_key;
        let b = &message.ciphertext;
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

    /// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
    /// and check the proof (which should pass).
    #[test]
    fn simulate_transcript_zero() {
        let group = elgamal::test::group();
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

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
        let extended_base_hash = elgamal::test::extended_base_hash();

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
        let extended_base_hash = elgamal::test::extended_base_hash();

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
}
