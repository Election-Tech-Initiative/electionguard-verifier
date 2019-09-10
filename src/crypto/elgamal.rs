use num::BigUint;
use num::traits::Pow;
use serde::{Deserialize, Serialize};
use crate::crypto::group::{Element, Exponent, generator};

/// An ElGamal message `(c, d)` encoding zero. This is useful because
/// you can only combine two ciphertexts if they both encode zero, as
/// in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = d bᶜ`. This acts as a
/// commitment to the one-time private key `t` used in this proof.
///
/// A message that has been encrypted using exponential ElGamal.
///
/// The encrypted message of the selection (the one or zero).
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Message {
    /// The one-time public key `a = gʳ`, where `r` is the randomly
    /// generated one-time public key.
    pub public_key: Element,

    /// The encoding `b = gᵐ hʳ`, where `m` is the cleartext and `h`
    /// is the recipient public key being used for encryption.
    pub ciphertext: Element,
}

impl Message {
    /// Encrypt `m` using `public_key` and a `one_time_secret` key.
    pub fn encrypt(
        public_key: &Element,
        m: &BigUint,
        one_time_secret: &Exponent,
    ) -> Message {
        let g = generator();
        let h = public_key;
        let r = one_time_secret;
        let m: Exponent = m.clone().into();
        let m = &m;

        // Let k = g^r. You can think of this as your one-time public key.
        let k = g.pow(r);

        // Normal Elgamal encryption: "Publish (k, m ⋅ h^r). I'll refer to the first element of the
        // pair as the one-time public key, the second element as the ciphertext, and the whole
        // pair as the encrypted message."
        // But we are instead using exponential Elgamal, which replaces `m` with `g^m`: "we make
        // one small tweak: instead of forming the ciphertext as m ⋅ g^(rs) where g^(rs) is that
        // shared secret, we use g^m ⋅ g^(rs)."
        Message {
            public_key: k,
            ciphertext: g.pow(m) * h.pow(r),
        }
    }

    /// Homomorphic addition of encrypted messages.  Converts the encryptions of `a` and `b` into
    /// the encryption of `a + b`.
    pub fn h_add(&self, other: &Message) -> Message {
        Message {
            public_key: &self.public_key * &other.public_key,
            ciphertext: &self.ciphertext * &other.ciphertext,
        }
    }

    /// Homomorphic negation of encrypted messages.  Converts the encryption of `a` into the
    /// encryption of `-a`.
    pub fn h_neg(&self) -> Message {
        Message {
            public_key: self.public_key.inverse(),
            ciphertext: self.ciphertext.inverse(),
        }
    }

    /// Homomorphic subtraction of encrypted messages.  Converts the encryptions of `a` and `b`
    /// into the encryption of `a - b`.
    pub fn h_sub(&self, other: &Message) -> Message {
        self.h_add(&other.h_neg())
    }
}


#[cfg(test)]
pub mod test {
    use num::BigUint;
    use super::*;

    pub fn private_key() -> Exponent {
        BigUint::from(2546_u32).into()
    }

    pub fn public_key() -> Element {
        generator().pow(&private_key())
    }

    pub fn extended_base_hash() -> BigUint {
        31268_u32.into()
    }
}
