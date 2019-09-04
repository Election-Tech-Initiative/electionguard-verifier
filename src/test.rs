use num::BigUint;
use num::traits::identities::{Zero, One};
use sha2::Sha256;
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{self, Group, Message};
use crate::crypto::hash;

/// Negation in the group with modulus `p`.
pub fn mod_neg(a: &BigUint, p: &BigUint) -> BigUint {
    (p - a % p) % p
}

/// Subtraction in the group with modulus `p`.
pub fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a % p + p - b % p) % p
}

/// Multiplicative inversion (reciprocal) in the group with prime modulus `p`.
pub fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    // https://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Using_Euler's_theorem
    // "In the special case where m is a prime, ϕ(m) = m-1, and a modular inverse is given by
    // a^-1 = a^(m-2) (mod m)."
    a.modpow(&(p - 2_u8), p)
}

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
    /// Use this `Proof` to establish that `message` is an encryption of zero under `public_key`.
    pub fn check_zero(
        &self,
        group: &Group,
        public_key: &BigUint,
        message: &Message,
    ) -> chaum_pederson::ResponseStatus {
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

        chaum_pederson::ResponseStatus {
            public_key: alpha_ok,
            ciphertext: beta_ok,
        }
    }

    /// Use this `Proof` to establish that `message1` is equal to `message2`.
    pub fn check_equal(
        &self,
        group: &Group,
        public_key: &BigUint,
        message1: &Message,
        message2: &Message,
    ) -> chaum_pederson::ResponseStatus {
        // Check that the decryptions of `message1` and `message2` are equal by proving that their
        // difference is zero.
        let combined_message = message1.h_sub(message2, group);
        self.check_zero(group, public_key, &combined_message)
    }

    /// Use this `Proof` to establish that `message` is an encryption of `plaintext`.
    pub fn check_plaintext(
        &self,
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        plaintext: &BigUint,
    ) -> chaum_pederson::ResponseStatus {
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
        self.check_equal(group, public_key, message, &encrypted_plaintext)
    }


    /// Construct a proof that `message` is an encryption of zero.  This requires knowing the
    /// `one_time_secret` key that was used to construct `message`.  The callback `gen_challenge`
    /// is used to generate a challenge given the commitment.
    pub fn prove_zero(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&Message) -> BigUint,
    ) -> chaum_pederson::Proof {
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
        let challenge = gen_challenge(&commitment);

        let c = &challenge;
        // "We response with u = t + cr like we would if this were a Schnorr proof for posession of
        // r."
        // (From the Schnorr proof section, which uses different notation:) "The prover responds to
        // the challenge with u = r + cs (mod p - 1), where s is the secret key they're trying to
        // show that they know."
        let u = (t + c * r) % &(p - 1_u8);

        chaum_pederson::Proof {
            committment: commitment,
            challenge: challenge,
            response: u,
        }
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
        gen_challenge: impl FnOnce(&Message) -> BigUint,
    ) -> chaum_pederson::Proof {
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

    /// Construct a proof that `message` is an encryption of `plaintext`.
    pub fn prove_plaintext(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        plaintext: &BigUint,
        one_time_exponent: &BigUint,
        gen_challenge: impl FnOnce(&Message) -> BigUint,
    ) -> chaum_pederson::Proof {
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
    /// `response`, it constructs a valid-seeming proof that `message` is an encryption of zero,
    /// regardless of the actual value of `message`.
    pub fn simulate_zero(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        challenge: &BigUint,
        response: &BigUint,
    ) -> chaum_pederson::Proof {
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

        chaum_pederson::Proof {
            committment: Message {
                public_key: alpha,
                ciphertext: beta,
            },
            challenge: c.clone(),
            response: u.clone(),
        }
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
    ) -> chaum_pederson::Proof {
        let combined_message = message1.h_sub(message2, group);
        Self::simulate_zero(
            group,
            public_key,
            &combined_message,
            challenge,
            response,
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
    ) -> chaum_pederson::Proof {
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


/// Encrypt a zero, construct a Chaum-Pederson proof that it's zero, and check the proof.
#[test]
fn prove_check_zero() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let one_time_secret = 2140_u32.into();
    let message = Message::encrypt(&group, &public_key, &0_u8.into(), &one_time_secret);
    let one_time_exponent = 3048_u32.into();
    let proof = chaum_pederson::Proof::prove_zero(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_zero(&group, &public_key, &message);
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
    let proof = chaum_pederson::Proof::prove_zero(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_zero(&group, &public_key, &message);
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
    let proof = chaum_pederson::Proof::prove_zero(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_zero(&group, &public_key, &message);
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

    let proof = chaum_pederson::Proof::prove_equal(
        &group,
        &public_key,
        &message1,
        &one_time_secret1,
        &message2,
        &one_time_secret2,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_equal(&group, &public_key, &message1, &message2);
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

    let proof = chaum_pederson::Proof::prove_equal(
        &group,
        &public_key,
        &message1,
        &one_time_secret1,
        &message2,
        &one_time_secret2,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_equal(&group, &public_key, &message1, &message2);
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

    let proof = chaum_pederson::Proof::prove_equal(
        &group,
        &public_key,
        &message1,
        &one_time_secret1,
        &message2,
        &one_time_secret2,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_equal(&group, &public_key, &message1, &message2);
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
    let proof = chaum_pederson::Proof::prove_plaintext(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &value,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_plaintext(&group, &public_key, &message, &value);
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
    let proof = chaum_pederson::Proof::prove_plaintext(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &other_value,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_plaintext(&group, &public_key, &message, &other_value);
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
    let proof = chaum_pederson::Proof::prove_plaintext(
        &group,
        &public_key,
        &message,
        &one_time_secret,
        &value,
        &one_time_exponent,
        |msg| hash_uints(&[&extended_base_hash, &msg.public_key, &msg.ciphertext]),
    );

    let status = proof.check_plaintext(&group, &public_key, &message, &value);
    dbg!(&status);
    assert!(status.is_ok());
}

/// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
/// and check the proof (which should pass).
#[test]
fn simulate_check_zero() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let value = 16351_u32.into();
    let one_time_secret = 18328_u32.into();
    let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
    let challenge = 11947_u32.into();
    let response = 30170_u32.into();
    let proof = chaum_pederson::Proof::simulate_zero(
        &group,
        &public_key,
        &message,
        &challenge,
        &response,
    );

    let status = proof.check_zero(&group, &public_key, &message);
    dbg!(&status);
    assert!(status.is_ok());
}

/// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
/// and check the proof (which should pass).
#[test]
fn simulate_check_equal() {
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
    let proof = chaum_pederson::Proof::simulate_equal(
        &group,
        &public_key,
        &message1,
        &message2,
        &challenge,
        &response,
    );

    let status = proof.check_equal(&group, &public_key, &message1, &message2);
    dbg!(&status);
    assert!(status.is_ok());
}

/// Encrypt a nonzero value, construct a fake proof that it's zero using a pre-selected challenge,
/// and check the proof (which should pass).
#[test]
fn simulate_check_plaintext() {
    let group = elgamal::test::group();
    let public_key = elgamal::test::public_key();
    let extended_base_hash = elgamal::test::extended_base_hash();

    let value = 15271_u32.into();
    let one_time_secret = 482_u32.into();
    let message = Message::encrypt(&group, &public_key, &value, &one_time_secret);
    let plaintext = 8049_u32.into();
    let challenge = 8508_u32.into();
    let response = 23843_u32.into();
    let proof = chaum_pederson::Proof::simulate_plaintext(
        &group,
        &public_key,
        &message,
        &plaintext,
        &challenge,
        &response,
    );

    let status = proof.check_plaintext(&group, &public_key, &message, &plaintext);
    dbg!(&status);
    assert!(status.is_ok());
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
