use serde::{Deserialize, Serialize};

use crate::crypto::elgamal;

use super::Share;

/// A decryption of the encrypted tally of a single option in a contest.
#[derive(Serialize, Deserialize)]
pub struct Tally {
    /// The actual tally encrypted.
    cleartext: u64,

    /// The decrypted tally `M`.
    decrypted_tally: u64,

    encrypted_tally: elgamal::Message,

    /// The decryption shares `M_i` used to compute the decrypted tally `M`.
    shares: Vec<Share>,
}
