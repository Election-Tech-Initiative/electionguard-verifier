use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{self, Group};
use crate::crypto::{chaum_pederson, hash};

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
    message: elgamal::Message,
    #[serde(flatten)]
    proof: chaum_pederson::disj::Proof,
}

#[derive(Debug, Serialize)]
pub struct Status {
    proof: chaum_pederson::disj::Status,
}

impl Selection {
    pub fn check<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> Status {
        use chaum_pederson::disj::HashInput::{Left, Right};
        use chaum_pederson::HashInput::{CommittmentCiphertext, CommittmentPublicKey};
        use hash::Input::{External, Proof};

        let hash_args = [
            External(extended_base_hash),
            External(&self.message.public_key),
            External(&self.message.ciphertext),
            Proof(Left(CommittmentCiphertext)),
            Proof(Left(CommittmentPublicKey)),
            Proof(Right(CommittmentCiphertext)),
            Proof(Right(CommittmentPublicKey)),
        ];

        Status {
            proof: self
                .proof
                .check(group, &self.message, public_key, hash::Spec(&hash_args)),
        }
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.proof.is_ok()
    }
}
