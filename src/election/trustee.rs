use num::bigint::BigUint;
use serde::Deserialize;

/// The values an election trustee commits to as part of the
/// non-interactive zero-knowledge Schnorr proof of possession of the
/// associated private key
#[derive(Deserialize)]
struct CoefCommittment {
    /// The trustee's ElGamal public key or coefficient, `K_i`
    public_key: BigUint,
    /// The hash input `h_i`
    hash_input: BigUint,
    /// The hash output `c_i`
    hash_output: [u8; 32],
    /// TODO maybe the challenge `ui`
    challenge: BigUint,
}

#[derive(Deserialize)]
pub struct Committment(Vec<CoefCommittment>);
