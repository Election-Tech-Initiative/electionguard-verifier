use num::BigUint;
use num::traits::identities::{Zero, One};

use crate::crypto::elgamal::Message;
use crate::schema::*;
use crate::crypto::hash::{hash_uuu, hash_umc, hash_umcc};

macro_rules! check {
    ($cond:expr) => {
        if !$cond { return false; }
    };
}

pub fn check(r: &Record) -> bool {
    // Parameters

    check!(r.parameters.num_trustees > BigUint::zero());
    check!(r.parameters.threshold > BigUint::zero());
    check!(r.parameters.threshold <= r.parameters.num_trustees);
    check!(false);  // TODO: group check

    // Trustee private keys

    check!(BigUint::from(r.trustee_public_keys.len()) == r.parameters.num_trustees);

    for tpk in &r.trustee_public_keys {
        check!(BigUint::from(tpk.coefficients.len()) == r.parameters.threshold);

        for tc in &tpk.coefficients {
            check!(tc.proof.check(
                &r.parameters.group,
                &r.joint_public_key,
                |key, comm| hash_uuu(&r.extended_base_hash, key, comm),
            ).is_ok());
        }
    }

    // Cast ballots

    for cb in &r.cast_ballots {
        check!(cb.contests.len() == r.contest_tallies.len());

        for (i, cc) in cb.contests.iter().enumerate() {
            if let Some(ct) = r.contest_tallies.get(i) {
                check!(cc.selections.len() == ct.selections.len());
            }
            check!(false);  // TODO: Check max_selections against canonical max

            for cs in &cc.selections {
                check!(cs.proof.check_zero_one(
                    &r.parameters.group,
                    &r.joint_public_key,
                    &cs.message,
                    |msg, comm0, comm1| hash_umcc(&r.extended_base_hash, msg, comm0, comm1),
                ).is_ok());
            }

            check!(cc.num_selections_proof.check_plaintext(
                &r.parameters.group,
                &r.joint_public_key,
                &compute_selection_sum(&cc.selections),
                &cc.max_selections,
                |msg, comm| hash_umc(&r.extended_base_hash, msg, comm),
            ).is_ok());
        }
    }

    // Contest tallies

    for (i, ct) in r.contest_tallies.iter().enumerate() {
        for (j, dv) in ct.selections.iter().enumerate() {
            check!(dv.encrypted_value == compute_encrypted_tally(&r.cast_ballots, i, j));
            check!(check_decrypted_value(r, dv));
        }
    }

    // Spoiled ballots

    for sb in &r.spoiled_ballots {
        check!(sb.contests.len() == r.contest_tallies.len());

        for (i, sc) in sb.contests.iter().enumerate() {
            if let Some(ct) = r.contest_tallies.get(i) {
                check!(sc.selections.len() == ct.selections.len());
            }

            for dv in &sc.selections {
                check!(check_decrypted_value(r, dv));
            }
        }
    }

    // Miscellaneous checks

    check!(r.base_hash == compute_base_hash(&r.parameters));
    check!(r.joint_public_key == compute_joint_public_key(&r.trustee_public_keys));
    check!(r.extended_base_hash ==
        compute_extended_base_hash(&r.base_hash, &r.trustee_public_keys));


    // If we got here, all checks passed
    true
}


fn check_decrypted_value(r: &Record, dv: &DecryptedValue) -> bool {
    check!(dv.decrypted_value ==
        r.parameters.group.generator.modpow(&dv.cleartext, &r.parameters.group.prime));

    check!(false);  // TODO: encrypted_value decrypts to decrypted_value

    for s in &dv.shares {
        if let Some(ref sr) = s.recovery {
            for f in &sr.fragments {
                check!(false);  // TODO: proof
                check!(false);  // TODO: other fragment checks?
            }
            check!(false); // TODO: all fragments' trustee indices are disjoint
            check!(false); // TODO: fragments are assembled to produce s.share
        }

        check!(false);  // TODO: proof
    }

    // If we got here, all checks passed
    true
}


fn compute_selection_sum(cast_selections: &[CastSelection]) -> Message {
    // (1, 1) is a valid encryption of zero for any key, with zero as the one-time secret.
    let mut sum = Message {
        public_key: BigUint::one(),
        ciphertext: BigUint::one(),
    };

    for cs in cast_selections {
        sum = sum.h_add(&cs.message, unimplemented!());
    }

    sum
}

fn compute_encrypted_tally(
    cast_ballots: &[CastBallot],
    contest_index: usize,
    selection_index: usize,
) -> Message {
    let mut sum = Message {
        public_key: BigUint::one(),
        ciphertext: BigUint::one(),
    };

    for cb in cast_ballots {
        if let Some(cc) = cb.contests.get(contest_index) {
            if let Some(cs) = cc.selections.get(selection_index) {
                sum = sum.h_add(&cs.message, unimplemented!());
            }
        }
    }

    sum
}

fn compute_base_hash(
    parameters: &Parameters,
) -> BigUint {
    BigUint::zero() // TODO
}

fn compute_joint_public_key(
    trustee_public_keys: &[TrusteePublicKey],
) -> BigUint {
    let mut product = BigUint::one();

    for tpk in trustee_public_keys {
        if let Some(tc) = tpk.coefficients.get(0) {
            product *= &tc.public_key;
        }
    }

    product
}

fn compute_extended_base_hash(
    base_hash: &BigUint,
    trustee_public_keys: &[TrusteePublicKey],
) -> BigUint {
    BigUint::zero() // TODO
}
