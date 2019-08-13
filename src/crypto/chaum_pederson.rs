use num::BigUint;
use serde::{Deserialize, Serialize};

use super::elgamal;

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
    /// The challenge value `c` that is produced by hashing relevent
    /// parameters, including the original ElGamal message `(a,b)` and
    /// the zero message `(c, d)`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    challenge: BigUint,

    /// An ElGamal message `(c, d)` encoding zero. This is useful
    /// because you can only combine two ciphertexts if they both
    /// encode zero, as in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = d
    /// bᶜ`. This acts as a committment to the one-time private key
    /// `t` used in this proof.
    committment: elgamal::Message,

    /// The response `u = t + c r mod (p-1)` to the challenge `c`,
    /// where `r` is the one-time private key used to encrypt the
    /// original message and `t` is the one-time private key used to
    /// encrypt the zero message used in this proof.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    response: BigUint,
}
