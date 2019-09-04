use num::BigUint;
use serde::{Deserialize, Serialize};

use super::selection::{self, Selection};
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{Group, Message};
use crate::crypto::hash;

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

fn inverse(a: &BigUint, p: &BigUint) -> BigUint {
    a.modpow(&(p - 2_u8), p)
}

impl Contest {
    pub fn check<'a>(
        &'a self,
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> Status {
        use chaum_pederson::HashInput::{CommittmentCiphertext, CommittmentPublicKey};
        use hash::Input::{External, Proof};

        let mut msg = homomorphic_selection_sum(&self.selections, &group.prime);
        msg.ciphertext *= inverse(
            &group.generator.modpow(&self.max_selections, &group.prime),
            &group.prime,
        );
        msg.ciphertext %= &group.prime;

        let hash_args = [
            External(extended_base_hash),
            // TODO: are these in the right order?
            External(&msg.public_key),
            External(&msg.ciphertext),
            Proof(CommittmentCiphertext),
            Proof(CommittmentPublicKey),
        ];

        Status {
            selections: self
                .selections
                .iter()
                .map(move |sel| sel.check(group, public_key, extended_base_hash))
                .collect(),
            num_selections: self
                .num_selections_proof
                .check(group, &msg, public_key, hash::Spec(&hash_args)),
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

#[cfg(test)]
pub mod test {
    use num::{Integer, BigUint};
    use crate::crypto::hash;
    use crate::crypto::elgamal::{self, Group, Message};
    use crate::crypto::hash::Spec;
    use crate::crypto::chaum_pederson::Proof;
    use crate::crypto::chaum_pederson::disj;
    use sha2::Sha256;
    use crate::encrypted::selection;
    use super::{Contest, homomorphic_selection_sum};

    fn inverse(a: &BigUint, p: &BigUint) -> BigUint {
        a.modpow(&(p - 2_u8), p)
    }

    fn hash_uints(xs: &[&BigUint]) -> BigUint {
        let inputs = xs.iter().map(|i| hash::Input::External(i)).collect::<Vec<_>>();
        hash::Spec::<()>(&inputs).exec::<_, Sha256>(|_| unreachable!())
    }

    pub fn mk() -> Contest {
        let Group { generator: g, prime: p } = elgamal::test::group();
        let h = elgamal::test::public_key();
        let q_bar = elgamal::test::extended_base_hash();

        let selections = vec![
            selection::test::mk_1(),
            selection::test::mk_1(),
        ];

        let L = 0_u8.into();

        let Message { public_key: A, ciphertext: B } = homomorphic_selection_sum(&selections, &p);

        let alpha = A;
        let beta = (&B * inverse(&g.modpow(&L, &p), &p)) % &p;

        let U = 32065_u32.into();
        let a = alpha.modpow(&U, &p);
        let b = beta.modpow(&U, &p);

        let C = hash_uints(&[&q_bar, &alpha, &beta, &b, &a]);
        let R = (selection::test::r_for_1() * selection::test::r_for_1()) % (&p - 1_u8);
        let V = (&U + &C * &R) % (&p - 1_u8);

        Contest {
            selections,
            max_selections: L,
            num_selections_proof: Proof {
                committment: Message {
                    public_key: a,
                    ciphertext: b,
                },
                challenge: C,
                response: V,
            },
        }
    }

    #[test]
    pub fn check() {
        let group = elgamal::test::group();
        let h = elgamal::test::public_key();
        let q_bar = elgamal::test::extended_base_hash();
        let status = mk().check(&group, &h, &q_bar);
        dbg!(&status);
        assert!(status.is_ok());
    }
}
