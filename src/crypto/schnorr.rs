use serde::{Deserialize, Serialize};

/// A proof of posession of the private key.
///
/// A non-interactive zero-knowledge proof of knowledge of a private
/// key `s` corresponding to a public key `h`.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    /// The challenge `c` that is produced by hashing relevent
    /// parameters, including the original public key `h` and the
    /// one-time public key `k`.
    challenge: u64,

    /// The one-use public key `k = gʳ` generated from the random
    /// one-use private key `r`. This acts as a committment to `r`.
    committment: u64,

    /// The response `u = r + c s mod (p - 1)` to the challenge, where
    /// `r` is the one-time private key corresponding to the one-time
    /// public key `k`, and `s` is the private-key corresponding to
    /// the original public key `h`.
    response: u64,
}
