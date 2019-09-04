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
        group: &'a Group,
        public_key: &'a BigUint,
        extended_base_hash: &'a BigUint,
    ) -> Status {
        use chaum_pederson::disj::HashInput::{Left, Right};
        use chaum_pederson::HashInput::{CommittmentCiphertext, CommittmentPublicKey};
        use hash::Input::{External, Proof};

        let hash_args = [
            External(extended_base_hash),
            // TODO: are these in the right order?
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

#[cfg(test)]
pub mod test {
    use num::{Integer, BigUint};
    use crate::crypto::hash;
    use crate::crypto::elgamal::{self, Group, Message};
    use crate::crypto::hash::Spec;
    use crate::crypto::chaum_pederson::Proof;
    use crate::crypto::chaum_pederson::disj;
    use sha2::Sha256;
    use super::Selection;

    fn inverse(a: &BigUint, p: &BigUint) -> BigUint {
        a.modpow(&(p - 2_u8), p)
    }

    fn hash_uints(xs: &[&BigUint]) -> BigUint {
        let inputs = xs.iter().map(|i| hash::Input::External(i)).collect::<Vec<_>>();
        hash::Spec::<()>(&inputs).exec::<_, Sha256>(|_| unreachable!())
    }

    pub fn r_for_0() -> BigUint {
        5779_u32.into()
    }

    pub fn mk_0() -> Selection {
        let Group { generator: g, prime: p } = elgamal::test::group();
        let h = elgamal::test::public_key();
        let q_bar = elgamal::test::extended_base_hash();

        // a random nonce r is selected uniformly from the range 0<r<p
        let r = r_for_0();

        // an encryption of zero is formed as α,β=(g^r mod p, h^r mod p)
        let alpha = g.modpow(&r, &p);
        let beta = h.modpow(&r, &p);

        // randomly select c1, v1, and u0
        let c1 = 9387_u32.into();
        let v1 = 25899_u32.into();
        let u0 = 31469_u32.into();

        // a0,b0 = g^u0 mod p, h^u0 mod p
        let a0 = g.modpow(&u0, &p);
        let b0 = h.modpow(&u0, &p);

        // a1,b1 = g^v1 / alpha^c1 mod p, h^v1 * g^ c1 / beta^c1 mod p
        let a1 = (g.modpow(&v1, &p) * inverse(&alpha.modpow(&c1, &p), &p)) % &p;
        let b1 = (h.modpow(&v1, &p) * g.modpow(&c1, &p) * inverse(&beta.modpow(&c1, &p), &p)) % &p;

        // form a challenge value c=H(Q,α,β,a0,b0,a1,b1)
        let c = hash_uints(&[&q_bar, &alpha, &beta, &b0, &a0, &b1, &a1]);

        // The proof is completed by forming c0=c-c1 mod p-1
        let c0 = (&c + (&p - 1_u8) - &c1) % (&p - 1_u8);
        // and v0=u0+c0⋅r mod p-1
        let v0 = (&u0 + &c0 * &r) % (&p - 1_u8);

        Selection {
            message: Message {
                public_key: alpha,
                ciphertext: beta,
            },
            proof: disj::Proof {
                left: Proof {
                    committment: Message {
                        public_key: a0,
                        ciphertext: b0,
                    },
                    challenge: c0,
                    response: v0,
                },
                right: Proof {
                    committment: Message {
                        public_key: a1,
                        ciphertext: b1,
                    },
                    challenge: c1,
                    response: v1,
                },
            },
        }
    }

    pub fn r_for_1() -> BigUint {
        31944_u32.into()
    }

    pub fn mk_1() -> Selection {
        let Group { generator: g, prime: p } = elgamal::test::group();
        let h = elgamal::test::public_key();
        let q_bar = elgamal::test::extended_base_hash();

        // a random nonce r is selected uniformly from the range 0<r<p
        let r = r_for_1();

        // an encryption of zero is formed as α,β=(g^r mod p, h^r mod p)
        let alpha = g.modpow(&r, &p);
        let beta = &g * h.modpow(&r, &p);

        // randomly select c0, v0, and u1
        let c0 = 15407_u32.into();
        let v0 = 23210_u32.into();
        let u1 = 25489_u32.into();

        // a0,b0 = g^v0 / alpha^c0 mod p, h^v0 * g^ c0 / beta^c0 mod p
        let a0 = (g.modpow(&v0, &p) * inverse(&alpha.modpow(&c0, &p), &p)) % &p;
        let b0 = (h.modpow(&v0, &p) * g.modpow(&c0, &p) * inverse(&beta.modpow(&c0, &p), &p)) % &p;

        // a1,b1 = g^u1 mod p, h^u1 mod p
        let a1 = g.modpow(&u1, &p);
        let b1 = h.modpow(&u1, &p);

        // form a challenge value c=H(Q,α,β,a0,b0,a1,b1)
        let c = hash_uints(&[&q_bar, &alpha, &beta, &b0, &a0, &b1, &a1]);

        // The proof is completed by forming c1=c-c0 mod p-1
        let c1 = (&c + (&p - 1_u8) - &c0) % (&p - 1_u8);
        // and v1=u1+c1⋅r mod p-1
        let v1 = (&u1 + &c1 * &r) % (&p - 1_u8);

        Selection {
            message: Message {
                public_key: alpha,
                ciphertext: beta,
            },
            proof: disj::Proof {
                left: Proof {
                    committment: Message {
                        public_key: a0,
                        ciphertext: b0,
                    },
                    challenge: c0,
                    response: v0,
                },
                right: Proof {
                    committment: Message {
                        public_key: a1,
                        ciphertext: b1,
                    },
                    challenge: c1,
                    response: v1,
                },
            },
        }
    }

    #[test]
    fn check_encrypted_0() {
        let group = elgamal::test::group();
        let h = elgamal::test::public_key();
        let q_bar = elgamal::test::extended_base_hash();
        let status = mk_0().check(&group, &h, &q_bar);
        dbg!(&status);
        assert!(status.is_ok());
    }

    #[test]
    fn check_encrypted_1() {
        let group = elgamal::test::group();
        let h = elgamal::test::public_key();
        let q_bar = elgamal::test::extended_base_hash();
        let status = mk_1().check(&group, &h, &q_bar);
        dbg!(&status);
        assert!(status.is_ok());
    }
}
