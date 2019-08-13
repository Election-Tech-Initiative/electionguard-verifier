use num::BigUint;
use serde::{Deserialize, Serialize};

/// An ElGamal message `(c, d)` encoding zero. This is useful because
/// you can only combine two ciphertexts if they both encode zero, as
/// in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = d bᶜ`. This acts as a
/// committment to the one-time private key `t` used in this proof.
///
/// A message that has been encrypted using exponential ElGamal.
///
/// The encrypted message of the selection (the one or zero).
#[derive(Serialize, Deserialize)]
pub struct Message {
    /// The encoding `b = gᵐ hʳ`, where `m` is the cleartext and `h`
    /// is the recipient public key being used for encryption.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    ciphertext: BigUint,

    /// The one-time public key `a = gʳ`, where `r` is the randomly
    /// generated one-time public key.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    public_key: BigUint,
}
