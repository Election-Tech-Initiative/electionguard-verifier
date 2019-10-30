use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::Message;
use crate::crypto::group::{Element, Exponent};

/// A pair of Chaum-Pedersen proof transcripts, used to prove that one of two properties is true
/// (without revealing which one).
///
/// If both transcripts are valid for their respective properties, and the sum of the two
/// challenges matches the expected value, then one of the properties holds.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "zero_proof")]
    pub left: super::Proof,
    #[serde(rename = "one_proof")]
    pub right: super::Proof,
}

#[derive(Debug, Serialize)]
pub struct Status {
    challenge: bool,
    response_left: super::ResponseStatus,
    response_right: super::ResponseStatus,
}

impl Proof {
    pub fn check_zero_one(
        &self,
        public_key: &Element,
        message: &Message,
        gen_challenge: impl FnOnce(&Message, &Message, &Message) -> BigUint,
    ) -> Status {
        let combined_challenge = &self.left.challenge + &self.right.challenge;
        let expected_challenge = Exponent::new(gen_challenge(
            message,
            &self.left.commitment,
            &self.right.commitment,
        ));
        let challenge_ok = combined_challenge == expected_challenge;

        let (response_left_status, response_right_status) =
            self.transcript_zero_one(public_key, message);

        Status {
            challenge: challenge_ok,
            response_left: response_left_status,
            response_right: response_right_status,
        }
    }

    pub fn transcript_zero_one(
        &self,
        public_key: &Element,
        message: &Message,
    ) -> (super::ResponseStatus, super::ResponseStatus) {
        (
            self.left
                .transcript_plaintext(public_key, message, &0_u8.into()),
            self.right
                .transcript_plaintext(public_key, message, &1_u8.into()),
        )
    }

    /// Given a `message` that's an encryption of zero, construct a proof that it's either an
    /// encryption of zero or an encryption of one.
    pub fn prove_zero(
        public_key: &Element,
        message: &Message,
        one_time_secret: &Exponent,
        real_one_time_exponent: &Exponent,
        fake_challenge: &Exponent,
        fake_response: &Exponent,
        mut gen_challenge: impl FnMut(&Message, &Message, &Message) -> BigUint,
    ) -> Proof {
        let proof_one = super::Proof::simulate_plaintext(
            public_key,
            message,
            &1_u8.into(),
            fake_challenge,
            fake_response,
        );
        let proof_zero = super::Proof::prove_plaintext(
            public_key,
            message,
            one_time_secret,
            &0_u8.into(),
            real_one_time_exponent,
            |_, commitment_zero| {
                let combined_challenge = gen_challenge(
                    // NB: the `message` used to compute the combined challenge is the message that
                    // we're proving to be 0/1.  The message provided to the callback by
                    // `prove_plaintext` is modified based on the plaintext value being compared
                    // against.
                    message,
                    commitment_zero,
                    &proof_one.commitment,
                );
                // This `a + -b` order makes sure we don't try to produce a negative BigUint.
                &combined_challenge + (-fake_challenge).as_uint().clone()
            },
        );
        Proof {
            left: proof_zero,
            right: proof_one,
        }
    }

    /// Given a `message` that's an encryption of one, construct a proof that it's either an
    /// encryption of zero or an encryption of one.
    pub fn prove_one(
        public_key: &Element,
        message: &Message,
        one_time_secret: &Exponent,
        real_one_time_exponent: &Exponent,
        fake_challenge: &Exponent,
        fake_response: &Exponent,
        mut gen_challenge: impl FnMut(&Message, &Message, &Message) -> BigUint,
    ) -> Proof {
        let proof_zero = super::Proof::simulate_plaintext(
            public_key,
            message,
            &0_u8.into(),
            fake_challenge,
            fake_response,
        );
        let proof_one = super::Proof::prove_plaintext(
            public_key,
            message,
            one_time_secret,
            &1_u8.into(),
            real_one_time_exponent,
            |_, commitment_one| {
                let combined_challenge = gen_challenge(
                    // NB: the `message` used to compute the combined challenge is the message that
                    // we're proving to be 0/1.  The message provided to the callback by
                    // `prove_plaintext` is modified based on the plaintext value being compared
                    // against.
                    message,
                    &proof_zero.commitment,
                    commitment_one,
                );
                &combined_challenge + (-fake_challenge).as_uint().clone()
            },
        );
        Proof {
            left: proof_zero,
            right: proof_one,
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.challenge && self.response_left.is_ok() && self.response_right.is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::Proof;
    use crate::crypto::elgamal::{self, Message};
    use crate::crypto::hash::hash_umcc;

    /// Encrypt the value zero, prove that it's either zero or one, and check both parts of the
    /// proof.
    #[test]
    fn prove_check_disj_zero() {
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = 8768_u32.into();
        let message = Message::encrypt(&public_key, &0_u8.into(), &one_time_secret);
        let real_one_time_exponent = 24256_u32.into();
        let fake_challenge = 30125_u32.into();
        let fake_response = 6033_u32.into();
        let proof = Proof::prove_zero(
            &public_key,
            &message,
            &one_time_secret,
            &real_one_time_exponent,
            &fake_challenge,
            &fake_response,
            |msg, comm0, comm1| hash_umcc(&extended_base_hash, msg, comm0, comm1),
        );

        let status = proof.check_zero_one(&public_key, &message, |msg, comm0, comm1| {
            hash_umcc(&extended_base_hash, msg, comm0, comm1)
        });
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt the value one, prove that it's either zero or one, and check both parts of the
    /// proof.
    #[test]
    fn prove_check_disj_one() {
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = 8768_u32.into();
        let message = Message::encrypt(&public_key, &1_u8.into(), &one_time_secret);
        let real_one_time_exponent = 24256_u32.into();
        let fake_challenge = 30125_u32.into();
        let fake_response = 6033_u32.into();
        let proof = Proof::prove_one(
            &public_key,
            &message,
            &one_time_secret,
            &real_one_time_exponent,
            &fake_challenge,
            &fake_response,
            |msg, comm0, comm1| hash_umcc(&extended_base_hash, msg, comm0, comm1),
        );

        let status = proof.check_zero_one(&public_key, &message, |msg, comm0, comm1| {
            hash_umcc(&extended_base_hash, msg, comm0, comm1)
        });
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt the value two, construct a proof that falsely claims it's either zero or one, and check
    /// both parts of the proof (which should fail).
    #[test]
    #[should_panic]
    fn prove_check_disj_two() {
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = 8768_u32.into();
        let message = Message::encrypt(&public_key, &2_u8.into(), &one_time_secret);
        let real_one_time_exponent = 24256_u32.into();
        let fake_challenge = 30125_u32.into();
        let fake_response = 6033_u32.into();
        let proof = Proof::prove_zero(
            &public_key,
            &message,
            &one_time_secret,
            &real_one_time_exponent,
            &fake_challenge,
            &fake_response,
            |msg, comm0, comm1| hash_umcc(&extended_base_hash, msg, comm0, comm1),
        );

        let status = proof.check_zero_one(&public_key, &message, |msg, comm0, comm1| {
            hash_umcc(&extended_base_hash, msg, comm0, comm1)
        });
        dbg!(&status);
        assert!(status.is_ok());
    }

    /// Encrypt the value zero, wrongly construct a proof using `prove_one`, and check both parts of
    /// the proof (which should fail).
    #[test]
    #[should_panic]
    fn prove_check_disj_one_flipped() {
        let public_key = elgamal::test::public_key();
        let extended_base_hash = elgamal::test::extended_base_hash();

        let one_time_secret = 8768_u32.into();
        let message = Message::encrypt(&public_key, &0_u8.into(), &one_time_secret);
        let real_one_time_exponent = 24256_u32.into();
        let fake_challenge = 30125_u32.into();
        let fake_response = 6033_u32.into();
        let proof = Proof::prove_one(
            &public_key,
            &message,
            &one_time_secret,
            &real_one_time_exponent,
            &fake_challenge,
            &fake_response,
            |msg, comm0, comm1| hash_umcc(&extended_base_hash, msg, comm0, comm1),
        );

        let status = proof.check_zero_one(&public_key, &message, |msg, comm0, comm1| {
            hash_umcc(&extended_base_hash, msg, comm0, comm1)
        });
        dbg!(&status);
        assert!(status.is_ok());
    }
}
