use num::BigUint;
use serde::{Deserialize, Serialize};

use super::elgamal::{Group, Message};

pub mod disj;

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
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    /// An ElGamal message `(α, β)` encoding zero. This is useful
    /// because you can only combine two ciphertexts if they both
    /// encode zero, as in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = β
    /// bᶜ`. This acts as a committment to the one-time private key
    /// `t` used in this proof.
    committment: Message,

    /// The challenge value `c` that is produced by hashing relevent
    /// parameters, including the original ElGamal message `(a,b)` and
    /// the zero message `(c, d)`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    challenge: BigUint,

    /// The response `u = t + c r mod (p-1)` to the challenge `c`,
    /// where `r` is the one-time private key used to encrypt the
    /// original message and `t` is the one-time private key used to
    /// encrypt the zero message used in this proof.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    response: BigUint,
}

#[derive(Debug, Serialize)]
pub struct ResponseStatus {
    public_key: bool,
    ciphertext: bool,
}

#[derive(Debug, Serialize)]
pub struct Status {
    challenge: bool,
    response: ResponseStatus,
}

#[derive(Debug, Copy, Clone)]
pub enum HashInput {
    CommittmentPublicKey,
    CommittmentCiphertext,
}

impl Proof {
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

    fn resolver<'a>(&'a self) -> impl Fn(HashInput) -> &'a BigUint {
        use HashInput::*;

        move |x| match x {
            CommittmentPublicKey => &self.committment.public_key,
            CommittmentCiphertext => &self.committment.ciphertext,
        }
    }
}

impl ResponseStatus {
    pub fn is_ok(&self) -> bool {
        self.public_key && self.ciphertext
    }
}
