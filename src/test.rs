use num::BigUint;
use num::traits::identities::{Zero, One};
use sha2::Sha256;
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{self, Group, Message};
use crate::crypto::hash;

pub fn hash_uints(xs: &[&BigUint]) -> BigUint {
    let inputs = xs.iter().map(|i| hash::Input::External(i)).collect::<Vec<_>>();
    hash::Spec::<()>(&inputs).exec::<_, Sha256>(|_| unreachable!())
}

impl Message {
    /// Encrypt `m` using `public_key` and a `one_time_secret` key.
    pub fn encrypt(group: &Group, public_key: &BigUint, m: &BigUint, one_time_secret: &BigUint) -> Message {
        let g = &group.generator;
        let p = &group.prime;
        let h = public_key;
        let r = one_time_secret;

        // Let k = g^r. You can think of this as your one-time public key.
        let k = g.modpow(r, p);

        // Normal Elgamal encryption: "Publish (k, m ⋅ h^r). I'll refer to the first element of the
        // pair as the one-time public key, the second element as the ciphertext, and the whole
        // pair as the encrypted message."
        // But we are instead using exponential Elgamal, which replaces `m` with `g^m`: "we make
        // one small tweak: instead of forming the ciphertext as m ⋅ g^(rs) where g^(rs) is that
        // shared secret, we use g^m ⋅ g^(rs)."
        Message {
            public_key: k,
            ciphertext: g.modpow(m, p) * h.modpow(r, p) % p,
        }
    }

    /// Encrypt the number zero using `public_key` and a `one_time_secret` key.
    pub fn zero(group: &Group, public_key: &BigUint, one_time_secret: &BigUint) -> Message {
        Message::encrypt(group, public_key, &BigUint::zero(), one_time_secret)
    }

    /// Encrypt the number one using `public_key` and a `one_time_secret` key.
    pub fn one(group: &Group, public_key: &BigUint, one_time_secret: &BigUint) -> Message {
        Message::encrypt(group, public_key, &BigUint::one(), one_time_secret)
    }

    /// Homomorphic addition of encrypted messages.  Converts the encryptions of `a` and `b` into
    /// the encryption of `a + b`.
    pub fn h_add(&self, other: &Message, group: &Group) -> Message {
        Message {
            public_key: &self.public_key * &other.public_key % &group.prime,
            ciphertext: &self.ciphertext * &other.ciphertext % &group.prime,
        }
    }

    /// Homomorphic negation of encrypted messages.  Converts the encryption of `a` into the
    /// encryption of `-a`.
    pub fn h_neg(&self, group: &Group) -> Message {
        Message {
            public_key: mod_inv(&self.public_key, &group.prime),
            ciphertext: mod_inv(&self.ciphertext, &group.prime),
        }
    }

    /// Homomorphic subtraction of encrypted messages.  Converts the encryptions of `a` and `b`
    /// into the encryption of `a - b`.
    pub fn h_sub(&self, other: &Message, group: &Group) -> Message {
        self.h_add(&other.h_neg(group), group)
    }
}

impl chaum_pederson::Proof {
}

impl chaum_pederson::disj::Proof {
    /// Given a `message` that's an encryption of zero, construct a proof that it's either an
    /// encryption of zero or an encryption of one.
    pub fn prove_zero(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        real_one_time_exponent: &BigUint,
        fake_challenge: &BigUint,
        fake_response: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> chaum_pederson::disj::Proof {
        let proof_one = chaum_pederson::Proof::simulate_plaintext(
            group,
            public_key,
            message,
            &1_u8.into(),
            fake_challenge,
            fake_response,
        );
        let proof_zero = chaum_pederson::Proof::prove_plaintext(
            group,
            public_key,
            message,
            one_time_secret,
            &0_u8.into(),
            real_one_time_exponent,
            |commitment_zero| {
                let combined_challenge = gen_challenge(commitment_zero, &proof_one.committment);
                mod_sub(&combined_challenge, fake_challenge, &(&group.prime - 1_u8))
            },
        );
        chaum_pederson::disj::Proof {
            left: proof_zero,
            right: proof_one,
        }
    }

    /// Given a `message` that's an encryption of one, construct a proof that it's either an
    /// encryption of zero or an encryption of one.
    pub fn prove_one(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        real_one_time_exponent: &BigUint,
        fake_challenge: &BigUint,
        fake_response: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> chaum_pederson::disj::Proof {
        let proof_zero = chaum_pederson::Proof::simulate_plaintext(
            group,
            public_key,
            message,
            &0_u8.into(),
            fake_challenge,
            fake_response,
        );
        let proof_one = chaum_pederson::Proof::prove_plaintext(
            group,
            public_key,
            message,
            one_time_secret,
            &1_u8.into(),
            real_one_time_exponent,
            |commitment_one| {
                let combined_challenge = gen_challenge(&proof_zero.committment, commitment_one);
                mod_sub(&combined_challenge, fake_challenge, &(&group.prime - 1_u8))
            },
        );
        chaum_pederson::disj::Proof {
            left: proof_zero,
            right: proof_one,
        }
    }

    pub fn challenge(&self, group: &Group) -> BigUint {
        (&self.left.challenge + &self.right.challenge) % &(&group.prime - 1_u8)
    }
}



/// Encrypt the value zero, prove that it's either zero or one, and check both parts of the proof.
#[test]
fn prove_check_disj_zero() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let one_time_secret = 8768_u32.into();
    let message = Message::encrypt(&group, &public_key, &0_u8.into(), &one_time_secret);
    let real_one_time_exponent = 24256_u32.into();
    let fake_challenge = 30125_u32.into();
    let fake_response = 6033_u32.into();
    let proof = chaum_pederson::disj::Proof::prove_zero(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &real_one_time_exponent,
        &fake_challenge,
        &fake_response,
        |comm0, comm1| hash_uints(&[
            &extended_base_hash,
            &comm0.public_key, &comm0.ciphertext,
            &comm1.public_key, &comm1.ciphertext,
        ]),
    );

    let status0 = proof.left.check_plaintext(&group, &public_key, &message, &0_u8.into());
    let status1 = proof.right.check_plaintext(&group, &public_key, &message, &1_u8.into());
    dbg!(&status0);
    dbg!(&status1);
    assert!(status0.is_ok());
    assert!(status1.is_ok());
}

/// Encrypt the value one, prove that it's either zero or one, and check both parts of the proof.
#[test]
fn prove_check_disj_one() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let one_time_secret = 8768_u32.into();
    let message = Message::encrypt(&group, &public_key, &1_u8.into(), &one_time_secret);
    let real_one_time_exponent = 24256_u32.into();
    let fake_challenge = 30125_u32.into();
    let fake_response = 6033_u32.into();
    let proof = chaum_pederson::disj::Proof::prove_one(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &real_one_time_exponent,
        &fake_challenge,
        &fake_response,
        |comm0, comm1| hash_uints(&[
            &extended_base_hash,
            &comm0.public_key, &comm0.ciphertext,
            &comm1.public_key, &comm1.ciphertext,
        ]),
    );

    let status0 = proof.left.check_plaintext(&group, &public_key, &message, &0_u8.into());
    let status1 = proof.right.check_plaintext(&group, &public_key, &message, &1_u8.into());
    dbg!(&status0);
    dbg!(&status1);
    assert!(status0.is_ok());
    assert!(status1.is_ok());
}

/// Encrypt the value two, construct a proof that falsely claims it's either zero or one, and check
/// both parts of the proof (which should fail).
#[test]
#[should_panic]
fn prove_check_disj_two() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let one_time_secret = 8768_u32.into();
    let message = Message::encrypt(&group, &public_key, &2_u8.into(), &one_time_secret);
    let real_one_time_exponent = 24256_u32.into();
    let fake_challenge = 30125_u32.into();
    let fake_response = 6033_u32.into();
    let proof = chaum_pederson::disj::Proof::prove_zero(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &real_one_time_exponent,
        &fake_challenge,
        &fake_response,
        |comm0, comm1| hash_uints(&[
            &extended_base_hash,
            &comm0.public_key, &comm0.ciphertext,
            &comm1.public_key, &comm1.ciphertext,
        ]),
    );

    let status0 = proof.left.check_plaintext(&group, &public_key, &message, &0_u8.into());
    let status1 = proof.right.check_plaintext(&group, &public_key, &message, &1_u8.into());
    dbg!(&status0);
    dbg!(&status1);
    assert!(status0.is_ok());
    assert!(status1.is_ok());
}

/// Encrypt the value zero, wrongly construct a proof using `prove_one`, and check both parts of
/// the proof (which should fail).
#[test]
#[should_panic]
fn prove_check_disj_one_flipped() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let one_time_secret = 8768_u32.into();
    let message = Message::encrypt(&group, &public_key, &0_u8.into(), &one_time_secret);
    let real_one_time_exponent = 24256_u32.into();
    let fake_challenge = 30125_u32.into();
    let fake_response = 6033_u32.into();
    let proof = chaum_pederson::disj::Proof::prove_one(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &real_one_time_exponent,
        &fake_challenge,
        &fake_response,
        |comm0, comm1| hash_uints(&[
            &extended_base_hash,
            &comm0.public_key, &comm0.ciphertext,
            &comm1.public_key, &comm1.ciphertext,
        ]),
    );

    let status0 = proof.left.check_plaintext(&group, &public_key, &message, &0_u8.into());
    let status1 = proof.right.check_plaintext(&group, &public_key, &message, &1_u8.into());
    dbg!(&status0);
    dbg!(&status1);
    assert!(status0.is_ok());
    assert!(status1.is_ok());
}
