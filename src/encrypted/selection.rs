use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal;
use crate::crypto::chaum_pederson;
use crate::crypto::hash::hash_umcc;
use crate::crypto::group::Element;

/// A single selection in a contest, which contains the encrypted
/// value of the selection (zero or one), as well as a zero-knowledge
/// proof that the encrypted value is either a zero or a one. Both a
/// proof that the selection is zero and a proof that the selection is
/// one are always included, but depending on the actual value of the
/// selection, one of the proofs is "faked" in a way that makes the
/// verification go through. The verifier cannot and (need not)
/// determine which proof is "real" and which is "faked", but instead
/// verifies that one of them must be real.
#[derive(Debug, Serialize, Deserialize)]
pub struct Selection {
    pub message: elgamal::Message,
    #[serde(flatten)]
    pub proof: chaum_pederson::disj::Proof,
}

#[derive(Debug, Serialize)]
pub struct Status {
    proof: chaum_pederson::disj::Status,
}

impl Selection {
    pub fn check<'a>(
        &'a self,
        public_key: &'a Element,
        extended_base_hash: &'a BigUint,
    ) -> Status {

        Status {
            proof: self.proof.check_zero_one(
               public_key,
               &self.message,
               |msg, comm0, comm1| hash_umcc(extended_base_hash, msg, comm0, comm1),
            ),
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.proof.is_ok()
    }
}

