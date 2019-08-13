use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal;

use super::Share;

/// A decryption of the encrypted tally of a single option in a contest.
#[derive(Serialize, Deserialize)]
pub struct Tally {
    /// The actual tally encrypted.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    cleartext: BigUint,

    /// The decrypted tally `M`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    decrypted_tally: BigUint,

    encrypted_tally: elgamal::Message,

    /// The decryption shares `M_i` used to compute the decrypted tally `M`.
    shares: Vec<Share>,
}
