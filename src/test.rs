use num::BigUint;
use num::traits::identities::{Zero, One};
use sha2::Sha256;
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{self, Group, Message};
use crate::crypto::hash;

/// Inversion (reciprocal) in the group with prime modulus `p`.
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
        // Check that `message` is equal to an encryption of `plaintext`.  The one-time "secret"
        // doesn't matter (we aren't trying to hide the value of `plaintext`), so we just use zero.
        let one_time_secret = 0_u8.into();
        let encrypted_plaintext = Message::encrypt(group, public_key, plaintext, &one_time_secret);
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
}


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
