use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::chaum_pederson;

mod ballot;
mod tally;

pub use ballot::{Ballot, Selection};
pub use tally::Tally;

/// A single trustee's share of a decryption of some encrypted message
/// `(a, b)`. The encrypted message can be an encrypted tally or an
/// encrypted ballot.
#[derive(Serialize, Deserialize)]
pub struct Share {
    /// The `k` fragments used to reconstruct this decryption share,
    /// if this trustee was absent.
    fragments: Option<Vec<Fragment>>,

    /// The proof that the share encodes the same value as the
    /// encrypted message.
    proof: chaum_pederson::Proof,

    /// The share of the decrypted message `M_i`.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    share: BigUint,
}

/// A fragment of a missing trustee's share of a decryption, including
/// the LaGrange coefficient.
#[derive(Serialize, Deserialize)]
pub struct Fragment {
    /// The actual fragment `M_{i,j}` which is trustee `j`'s piece of
    /// the missing trustee `i`'s share of a decryption.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    fragment: BigUint,

    /// The LaGrange coefficient `w_{i,j}` used to compute the
    /// decryption share from the fragments.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    lagrange_coefficient: BigUint,

    /// The proof that the fragment encodes the same values as the
    /// encrypted message
    proof: chaum_pederson::Proof,

    /// The index of the trustee who produced this fragment.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    trustee_index: BigUint,
}

#[derive(Debug, Serialize)]
pub struct ShareStatus {
    /// Are the fragments valid?
    fragments: Option<Vec<FragmentStatus>>,
    proof: chaum_pederson::Status,
}

#[derive(Debug, Serialize)]
pub struct FragmentStatus {
    // TODO
    //proof: chaum_pederson::Status,
}
