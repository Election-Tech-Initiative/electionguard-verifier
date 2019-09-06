use num::BigUint;
use num::traits::{Zero, One, Pow};

use crate::crypto::group::{Element, Exponent, generator};
use crate::crypto::elgamal::Message;
use crate::schema::*;
use crate::crypto::hash::{hash_uee, hash_umc, hash_umcc};

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
                &r.joint_public_key,
                |key, comm| hash_uee(&r.extended_base_hash, key, comm),
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
                    &r.joint_public_key,
                    &cs.message,
                    |msg, comm0, comm1| hash_umcc(&r.extended_base_hash, msg, comm0, comm1),
                ).is_ok());
            }

            check!(cc.num_selections_proof.check_plaintext(
                &r.joint_public_key,
                &compute_selection_sum(&cc.selections),
                &cc.max_selections,
                |msg, comm| hash_umc(&r.extended_base_hash, msg, comm),
            ).is_ok());
        }
    }

    // Contest tallies

    for (i, ct) in r.contest_tallies.iter().enumerate() {
        for (j, dt) in ct.selections.iter().enumerate() {
            check!(dt.value.encrypted_value == compute_encrypted_tally(&r.cast_ballots, i, j));
            check!(check_decrypted_value(r, &dt.value));
        }
    }

    // Spoiled ballots

    for sb in &r.spoiled_ballots {
        check!(sb.contests.len() == r.contest_tallies.len());

        for (i, sc) in sb.contests.iter().enumerate() {
            if let Some(ct) = r.contest_tallies.get(i) {
                check!(sc.selections.len() == ct.selections.len());
            }

            for ds in &sc.selections {
                check!(check_decrypted_value(r, &ds.value));
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
    check!(dv.decrypted_value == generator().pow(&dv.cleartext));

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


pub fn compute_selection_sum(cast_selections: &[CastSelection]) -> Message {
    // (1, 1) is a valid encryption of zero for any key, with zero as the one-time secret.
    let mut sum = Message {
        public_key: Element::one(),
        ciphertext: Element::one(),
    };

    for cs in cast_selections {
        sum = sum.h_add(&cs.message);
    }

    sum
}

pub fn compute_encrypted_tally(
    cast_ballots: &[CastBallot],
    contest_index: usize,
    selection_index: usize,
) -> Message {
    let mut sum = Message {
        public_key: Element::one(),
        ciphertext: Element::one(),
    };

    for cb in cast_ballots {
        if let Some(cc) = cb.contests.get(contest_index) {
            if let Some(cs) = cc.selections.get(selection_index) {
                sum = sum.h_add(&cs.message);
            }
        }
    }

    sum
}

pub fn compute_base_hash(
    parameters: &Parameters,
) -> BigUint {
    BigUint::zero() // TODO
}

pub fn compute_joint_public_key(
    trustee_public_keys: &[TrusteePublicKey],
) -> Element {
    let mut product = Element::one();

    for tpk in trustee_public_keys {
        if let Some(tc) = tpk.coefficients.get(0) {
            product = &product * &tc.public_key;
        }
    }

    product
}

pub fn compute_extended_base_hash(
    base_hash: &BigUint,
    trustee_public_keys: &[TrusteePublicKey],
) -> BigUint {
    BigUint::zero() // TODO
}
