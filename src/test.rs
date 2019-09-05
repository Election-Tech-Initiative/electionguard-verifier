use num::BigUint;
use sha2::Sha256;
use crate::crypto::chaum_pederson;
use crate::crypto::elgamal::{self, Group, Message};
use crate::crypto::hash;

pub fn hash_uints(xs: &[&BigUint]) -> BigUint {
    let inputs = xs.iter().map(|i| hash::Input::External(i)).collect::<Vec<_>>();
    hash::Spec::<()>(&inputs).exec::<_, Sha256>(|_| unreachable!())
}

impl chaum_pederson::Proof {
}

impl chaum_pederson::disj::Proof {
    /// Given a `message` that's an encryption of zero, construct a proof that it's either an
    /// encryption of zero or an encryption of one.
    pub fn prove_zero(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        real_one_time_exponent: &BigUint,
        fake_challenge: &BigUint,
        fake_response: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> chaum_pederson::disj::Proof {
        let proof_one = chaum_pederson::Proof::simulate_plaintext(
            group,
            public_key,
            message,
            &1_u8.into(),
            fake_challenge,
            fake_response,
        );
        let proof_zero = chaum_pederson::Proof::prove_plaintext(
            group,
            public_key,
            message,
            one_time_secret,
            &0_u8.into(),
            real_one_time_exponent,
            |commitment_zero| {
                let combined_challenge = gen_challenge(commitment_zero, &proof_one.committment);
                mod_sub(&combined_challenge, fake_challenge, &(&group.prime - 1_u8))
            },
        );
        chaum_pederson::disj::Proof {
            left: proof_zero,
            right: proof_one,
        }
    }

    /// Given a `message` that's an encryption of one, construct a proof that it's either an
    /// encryption of zero or an encryption of one.
    pub fn prove_one(
        group: &Group,
        public_key: &BigUint,
        message: &Message,
        one_time_secret: &BigUint,
        real_one_time_exponent: &BigUint,
        fake_challenge: &BigUint,
        fake_response: &BigUint,
        gen_challenge: impl FnOnce(&Message, &Message) -> BigUint,
    ) -> chaum_pederson::disj::Proof {
        let proof_zero = chaum_pederson::Proof::simulate_plaintext(
            group,
            public_key,
            message,
            &0_u8.into(),
            fake_challenge,
            fake_response,
        );
        let proof_one = chaum_pederson::Proof::prove_plaintext(
            group,
            public_key,
            message,
            one_time_secret,
            &1_u8.into(),
            real_one_time_exponent,
            |commitment_one| {
                let combined_challenge = gen_challenge(&proof_zero.committment, commitment_one);
                mod_sub(&combined_challenge, fake_challenge, &(&group.prime - 1_u8))
            },
        );
        chaum_pederson::disj::Proof {
            left: proof_zero,
            right: proof_one,
        }
    }

    pub fn challenge(&self, group: &Group) -> BigUint {
        (&self.left.challenge + &self.right.challenge) % &(&group.prime - 1_u8)
    }
}


