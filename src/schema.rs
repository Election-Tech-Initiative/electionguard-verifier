use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::ballot;
use crate::crypto::chaum_pedersen;
use crate::crypto::elgamal;
use crate::crypto::schnorr;
use crate::crypto::group::{Element, Coefficient};

/// All the parameters necessary to form the election.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Parameters {
    /// The date on which the election takes place.
    pub date: String,

    /// The location where the election takes place
    pub location: String,

    /// The number of election trustees `n`.
    #[serde(with = "crate::serialize::big_uint")]
    pub num_trustees: BigUint,

    /// The threshold `k` of trustees required to complete
    /// verification.
    #[serde(with = "crate::serialize::big_uint")]
    pub threshold: BigUint,

    /// The prime modulus of the group used for encryption.
    #[serde(with = "crate::serialize::big_uint")]
    pub prime: BigUint,

    /// The generator of the group used for encryption.
    pub generator: Element,
}

/// All data from an ElectionGuard election
#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub parameters: Parameters,

    /// The base hash `Q` which is a SHA-256 hash of eleciton
    /// parameters including the prime modulus, generator, number of
    /// trustees, decryption threshold value, date, and jurisdictional
    /// information, as well as the contest configurations.
    #[serde(with = "crate::serialize::hash")]
    pub base_hash: BigUint,

    /// The public key and coefficient commitments for each trustee.
    pub trustee_public_keys: Vec<TrusteePublicKey>,

    /// The election public key `K`.
    pub joint_public_key: Element,

    /// The extended base hash `Q̅`.
    #[serde(with = "crate::serialize::hash")]
    pub extended_base_hash: BigUint,

    /// The encrypted ballots cast in the election.
    pub cast_ballots: Vec<CastBallot>,

    /// The decryptions of the tallies of each option for each
    /// contests in the election.
    pub contest_tallies: Vec<ContestTally>,

    /// The decryptions of the ballots spoiled in the election,
    /// including their encrypted selections, their decrypted
    /// selections, the cleartext of each selection, and proofs of the
    /// correctness of the decryptions.
    pub spoiled_ballots: Vec<SpoiledBallot>,
}


#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TrusteePublicKey {
    /// Each trustee generates `k` secret coefficients, and generates a public key from each one.
    /// The first such key is trustee's main public key (that is, `Ki = K_i0`); the rest are used
    /// during decryption if this trustee is absent.
    pub coefficients: Vec<TrusteeCoefficient>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TrusteeCoefficient {
    /// The public key `K_ij`generated from secret coefficient `a_ij`.
    pub public_key: Element,

    /// A proof of posession of the private key.
    pub proof: schnorr::Proof,
}


/// An encrypted ballot, consisting of the encrypted selections for
/// each contest, their proofs of well-formedness, and information
/// about where and when the ballot was encrypted.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CastBallot {
    pub ballot_info: ballot::Information,
    pub contests: Vec<CastContest>,
}

/// A contests consists of a list of encrypted selections, along with
/// a proof that exactly `L` of them have been selected.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CastContest {
    /// The encrypted selections made on the ballot.
    pub selections: Vec<CastSelection>,

    /// The maximum number of selections `L` that can be made in this
    /// contest.
    #[serde(with = "crate::serialize::big_uint")]
    pub max_selections: BigUint,

    /// Proof that the sum of the selections is equal to `L`.
    pub num_selections_proof: chaum_pedersen::Proof,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CastSelection {
    /// The value of this selection.  This is an encryption of either zero or one.
    pub message: elgamal::Message,
    /// Proof that either `message` is encryption of zero or `message` is the encryption of one.
    #[serde(flatten)]
    pub proof: chaum_pedersen::disj::Proof,
}


#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContestTally {
    /// The summed tallies for all selections in this contest.
    pub selections: Vec<SelectionTally>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SelectionTally {
    #[serde(serialize_with = "crate::serialize::decrypted_tally::serialize")]
    pub value: DecryptedValue,
}


/// A decryption of an encrypted ballot that was spoiled.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SpoiledBallot {
    pub ballot_info: ballot::Information,
    pub contests: Vec<SpoiledContest>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpoiledContest {
    pub selections: Vec<SpoiledSelection>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpoiledSelection {
    #[serde(serialize_with = "crate::serialize::decrypted_selection::serialize")]
    pub value: DecryptedValue,
}


/// The decryption of an encrypted value, with proofs that it was decrypted properly.
// This struct has custom serialization, since its fields are serialized with different names in
// different contexts.
#[derive(PartialEq, Eq, Debug, Deserialize)]
pub struct DecryptedValue {
    /// The cleartext value `t`.
    #[serde(with = "crate::serialize::big_uint")]
    pub cleartext: BigUint,

    /// The decrypted value `M = g^t`.
    #[serde(alias = "decrypted_message")]
    #[serde(alias = "decrypted_tally")]
    pub decrypted_value: Element,

    /// The encryption of `t`.  Decrypting this reveals `g^t`, which is `decrypted_value` above.
    #[serde(alias = "encrypted_message")]
    #[serde(alias = "encrypted_tally")]
    pub encrypted_value: elgamal::Message,

    /// The decryption shares `M_i` used to compute the decrypted value `M`.
    pub shares: Vec<Share>,
}

/// A single trustee's share of a decryption of some encrypted message `(a, b)`. The encrypted
/// message can be an encrypted tally or a selection from an encrypted ballot.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Share {
    /// The information used to reconstruct this decryption share, if this trustee was absent
    /// during decryption.
    pub recovery: Option<ShareRecovery>,

    /// The proof that the share was properly derived from the message and the trustee's secret
    /// key.  This is `None` if the trustee was absent - in that case, the share should be checked
    /// against the recovery fragments instead.
    pub proof: Option<chaum_pedersen::Proof>,

    /// The share of the decrypted message `M_i`.
    pub share: Element,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ShareRecovery {
    /// The `k` fragments used to reconstruct this decryption share,
    /// if this trustee was absent.
    pub fragments: Vec<Fragment>,
}

/// A fragment of a missing trustee's share of a decryption, including
/// the Lagrange coefficient.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Fragment {
    /// The actual fragment `M_{i,j}` which is trustee `j`'s piece of
    /// the missing trustee `i`'s share of a decryption.
    pub fragment: Element,

    /// The Lagrange coefficient `w_{i,j}` used to compute the
    /// decryption share from the fragments.
    pub lagrange_coefficient: Coefficient,

    /// The proof that the fragment encodes the same values as the
    /// encrypted message
    pub proof: chaum_pedersen::Proof,

    /// The index of the trustee who produced this fragment.
    #[serde(with = "crate::serialize::big_uint")]
    pub trustee_index: BigUint,
}
