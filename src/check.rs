use num::BigUint;
use num::traits::{Zero, One, Pow};

use crate::crypto::group::{Element, Exponent, generator};
use crate::crypto::elgamal::Message;
use crate::schema::*;
use crate::crypto::hash::{hash_uee, hash_umc, hash_umcc};
use crate::errors::ErrorContext;

pub fn check(r: &Record) -> Result<(), Vec<String>> {
    let mut err_list = Vec::new();
    check_record(&mut ErrorContext::new(&mut err_list), r);
    if err_list.len() == 0 {
        Ok(())
    } else {
        Err(err_list)
    }
}

pub fn check_record(errs: &mut ErrorContext, r: &Record) {
    // Parameters

    errs.check(r.parameters.num_trustees > BigUint::zero(),
        "num_trustees must be nonzero");
    errs.check(r.parameters.threshold > BigUint::zero(),
        "threshold must be nonzero");
    errs.check(r.parameters.threshold <= r.parameters.num_trustees,
        "threshold must not exceed num_trustees");
    errs.check(false, "TODO: group check");

    // Trustee private keys

    errs.check(BigUint::from(r.trustee_public_keys.len()) == r.parameters.num_trustees,
        "wrong number of public trustee public keys");

    for (i, tpk) in r.trustee_public_keys.iter().enumerate() {
        let mut errs = errs.scope(&format!("trustee public key #{}", i));
        errs.check(BigUint::from(tpk.coefficients.len()) == r.parameters.threshold,
            "wrong number of coefficients");

        for (j, tc) in tpk.coefficients.iter().enumerate() {
            let mut errs = errs.scope(&format!("coefficient #{}", j));
            errs.check(tc.proof.check(
                &r.joint_public_key,
                |key, comm| hash_uee(&r.extended_base_hash, key, comm),
            ).is_ok(), "invalid Schnorr proof of key ownership");
        }
    }

    // Cast ballots

    for (i, cb) in r.cast_ballots.iter().enumerate() {
        let mut errs = errs.scope(&format!("cast ballot #{}", i));
        errs.check(cb.contests.len() == r.contest_tallies.len(),
            "wrong number of contests");

        for (j, cc) in cb.contests.iter().enumerate() {
            let mut errs = errs.scope(&format!("contest #{}", j));
            if let Some(ct) = r.contest_tallies.get(j) {
                errs.check(cc.selections.len() == ct.selections.len(),
                    "wrong number of selections for contest");
            }
            errs.check(false, "TODO: max_selections check");

            for (k, cs) in cc.selections.iter().enumerate() {
                let mut errs = errs.scope(&format!("selection #{}", k));
                errs.check(cs.proof.check_zero_one(
                    &r.joint_public_key,
                    &cs.message,
                    |msg, comm0, comm1| hash_umcc(&r.extended_base_hash, msg, comm0, comm1),
                ).is_ok(), "invalid Chaum-Pedersen disjunction proof");
            }

            errs.check(cc.num_selections_proof.check_plaintext(
                &r.joint_public_key,
                &compute_selection_sum(&cc.selections),
                &cc.max_selections,
                |msg, comm| hash_umc(&r.extended_base_hash, msg, comm),
            ).is_ok(), "invalid Chaum-Pedersen proof for selection total");
        }
    }

    // Contest tallies

    for (i, ct) in r.contest_tallies.iter().enumerate() {
        let mut errs = errs.scope(&format!("contest tally #{}", i));
        for (j, st) in ct.selections.iter().enumerate() {
            let mut errs = errs.scope(&format!("selection tally #{}", j));
            errs.check(st.value.encrypted_value == compute_encrypted_tally(&r.cast_ballots, i, j),
                "encrypted sum was not computed correctly");
            check_decrypted_value(&mut errs, r, &st.value);
        }
    }

    // Spoiled ballots

    for (i, sb) in r.spoiled_ballots.iter().enumerate() {
        let mut errs = errs.scope(&format!("spoiled ballot #{}", i));
        errs.check(sb.contests.len() == r.contest_tallies.len(),
            "wrong number of contests");

        for (j, sc) in sb.contests.iter().enumerate() {
            let mut errs = errs.scope(&format!("contest #{}", j));
            if let Some(ct) = r.contest_tallies.get(j) {
                errs.check(sc.selections.len() == ct.selections.len(),
                    "wrong number of selections for contest");
            }

            for (k, ss) in sc.selections.iter().enumerate() {
                let mut errs = errs.scope(&format!("selection #{}", k));
                check_decrypted_value(&mut errs, r, &ss.value);
            }
        }
    }

    // Miscellaneous checks

    errs.check(r.base_hash == compute_base_hash(&r.parameters),
        "base hash was not computed correctly");
    errs.check(r.joint_public_key == compute_joint_public_key(&r.trustee_public_keys),
        "joint public key was not computed correctly");
    errs.check(r.extended_base_hash ==
        compute_extended_base_hash(&r.base_hash, &r.trustee_public_keys),
        "extended base hash was not computed correctly");
}


fn check_decrypted_value(errs: &mut ErrorContext, r: &Record, dv: &DecryptedValue) {
    errs.check(dv.decrypted_value == generator().pow(&dv.cleartext),
        "decrypted value does not match cleartext");

    errs.check(false, "TODO: encrypted_value decrypts to decrypted_value");

    for (i, s) in dv.shares.iter().enumerate() {
        if let Some(ref sr) = s.recovery {
            for (j, f) in sr.fragments.iter().enumerate() {
                errs.check(false, "TODO: chaum-pedersen proof");
                errs.check(false, "TODO: other fragment checks?");
            }
            errs.check(false, "TODO: trustee indices are disjoint");
            errs.check(false, "TODO: fragments are assembled correctly");
        }

        errs.check(false, "TODO: proof");  // TODO: proof
    }
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
