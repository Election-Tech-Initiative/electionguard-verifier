use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::ballot;
use crate::crypto::elgamal;

use super::Share;

/// A decryption of an encrypted ballot that was spoiled.
#[derive(Serialize, Deserialize)]
pub struct Ballot {
    ballot_info: ballot::Information,
    contests: Vec<Vec<Selection>>,
}

/// The decryption of the selection, including the encrypted message,
/// the decrypted message, the decryption shares, and the cleartext.
#[derive(Serialize, Deserialize)]
pub struct Selection {
    /// The actual value encrypted, so either a zero or a one.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    cleartext: BigUint,

    /// The decrypted message of the selection.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    decrypted_message: BigUint,

    /// The encrypted message of the selection (the one or zero).
    encrypted_message: elgamal::Message,

    /// The decryption shares `M_i` used to compute the decryption `M`.
    shares: Vec<Share>,
}
