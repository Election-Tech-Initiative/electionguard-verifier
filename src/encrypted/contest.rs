use num::BigUint;
use serde::{Deserialize, Serialize};

use super::selection::{self, Selection};
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{Group, Message};
use crate::crypto::hash::hash_umc;

/// A contests consists of a list of encrypted selections, along with
/// a proof that exactly `L` of them have been selected.
#[derive(Serialize, Deserialize)]
pub struct Contest {
    /// The encrypted selections made on the ballot.
    pub selections: Vec<Selection>,

    /// The maximum number of selections `L` that can be made in this
    /// contest.
    #[serde(deserialize_with = "crate::deserialize::biguint")]
    pub max_selections: BigUint,

    /// A proof that the sum of the selections is equal to `L`, by
    /// proving that their difference is zero.
    pub num_selections_proof: chaum_pederson::Proof,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub selections: Vec<selection::Status>,
    pub num_selections: chaum_pederson::Status,
}

impl Contest {
    pub fn check<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> Status {
        let selection_sum_message = self.selections.iter().fold(
            Message::encrypt(group, public_key, &0_u8.into(), &0_u8.into()),
            |cur, sel| cur.h_add(&sel.message, group),
        );

        Status {
            selections: self.selections.iter()
                .map(move |sel| sel.check(group, public_key, extended_base_hash))
                .collect(),
            num_selections: self.num_selections_proof.check_plaintext(
                group,
                public_key,
                &selection_sum_message,
                &self.max_selections,
                |msg, comm| hash_umc(extended_base_hash, msg, comm),
            ),
        }
    }
}

fn homomorphic_selection_sum(sels: &[Selection], p: &BigUint) -> Message {
    let mut msg = Message {
        public_key: 1_u8.into(),
        ciphertext: 1_u8.into(),
    };
    for s in sels {
        msg.public_key *= &s.message.public_key;
        msg.ciphertext *= &s.message.ciphertext;
    }
    msg.public_key %= p;
    msg.ciphertext %= p;

    msg
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.selections.iter().all(selection::Status::is_ok) &&
        self.num_selections.is_ok()
    }
}
