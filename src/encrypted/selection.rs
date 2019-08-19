use num::BigUint;
use serde::{Deserialize, Serialize};

use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{self, Group};

/// A single selection in a contest, which contains the encrypted
/// value of the selection (zero or one), as well as a zero-knowledge
/// proof that the encrypted value is either a zero or a one. Both a
/// proof that the selection is zero and a proof that the selection is
/// one are always included, but depending on the actual value of the
/// selection, one of the proofs is "faked" in a way that makes the
/// verification go through. The verifier cannot and (need not)
/// determine which proof is "real" and which is "faked", but instead
/// verifies that one of them must be real.
#[derive(Serialize, Deserialize)]
pub struct Selection {
    message: elgamal::Message,
    one_proof: chaum_pederson::Proof,
    zero_proof: chaum_pederson::Proof,
}

impl Selection {
    pub fn verify<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> impl Iterator<Item = chaum_pederson::Error> + 'a {
        use chaum_pederson::DisjHashInput::*;

        // Specify that c = H(Q̅, (α, β), (a₀, b₀), (a₁, b₁))
        let hash_order = [
            Custom(extended_base_hash.to_bytes_be()),
            Message,
            LeftCommittment,
            RightCommittment,
        ];

        chaum_pederson::Proof::verify_disj(
            &self.one_proof,
            &self.zero_proof,
            group,
            &self.message,
            public_key,
            &hash_order,
        )
    }
}
