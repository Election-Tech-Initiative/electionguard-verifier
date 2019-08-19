use digest::Digest;
use num::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::iter;

use super::elgamal::{self, Group, Message};

/// A proof that the sum of the selections is equal to `L`, by proving
/// that their difference is zero.
///
/// A non-interactive zero-knowledge Chaum-Pederson proof shows that
/// an ElGamal message `(a,b) = (gʳ, gᵐ hʳ)` is actually an encryption
/// of zero (`m = 0`) without revealing the nonce `r` used to encode
/// it. This can be used to show that two ElGamal messages encrypt the
/// same message, by creating a Chaum-Pederson proof for their
/// quotient `(a₁/a₂, b₁/b₂) = (gʳ¹⁻ʳ², gᵐ¹⁻ᵐ² hʳ¹⁻ʳ²)`.
///
/// The proof that the fragment encodes the same values as the
/// encrypted message
///
/// The proof that the share encodes the same value as the encrypted
/// message.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// An ElGamal message `(α, β)` encoding zero. This is useful
    /// because you can only combine two ciphertexts if they both
    /// encode zero, as in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = β
    /// bᶜ`. This acts as a committment to the one-time private key
    /// `t` used in this proof.
    pub committment: Message,

    /// The challenge value `c` that is produced by hashing relevent
    /// parameters, including the original ElGamal message `(a,b)` and
    /// the zero message `(c, d)`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub challenge: BigUint,

    /// The response `u = t + c r mod (p-1)` to the challenge `c`,
    /// where `r` is the one-time private key used to encrypt the
    /// original message and `t` is the one-time private key used to
    /// encrypt the zero message used in this proof.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub response: BigUint,
}

impl Proof {
    /// Verify that the first component of the response (the one-time public key) is correct:
    /// `gᵘ = α aᶜ`.
    ///
    /// # Parameters
    /// - `group`: the ElGamal group for the message, `(p, g)`
    /// - `message`: the message we want to prove encodes zero, `(a,
    ///    b) = (gʳ, m hʳ)`, where `r` is the private key used to
    ///    encrypt the message.
    #[allow(clippy::many_single_char_names)]
    fn verify_response_public_key(&self, group: &Group, message: &Message) -> bool {
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
    fn verify_response_ciphertext(
        &self,
        group: &Group,
        message: &Message,
        public_key: &BigUint,
    ) -> bool {
        let Group { prime: p, .. } = group;
        let Proof {
            committment: Message {
                ciphertext: beta, ..
            },
            challenge: c,
            response: u,
        } = self;
        let Message { ciphertext: b, .. } = message;
        let h = public_key;

        BigUint::modpow(h, u, p) == (beta * BigUint::modpow(b, c, p)) % p
    }
}
