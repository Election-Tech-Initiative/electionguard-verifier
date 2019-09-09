use num::BigUint;
use num::traits::{Zero, One, Pow};

use crate::crypto::group::{self, Element, Exponent, Coefficient, generator};
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
    errs.check(&r.parameters.prime == group::prime(),
        "election record uses unsupported group modulus");
    errs.check(&r.parameters.generator == group::generator(),
        "election record uses unsupported group generator");

    // Trustee private keys

    errs.check(BigUint::from(r.trustee_public_keys.len()) == r.parameters.num_trustees,
        "wrong number of public trustee public keys");

    for (i, tpk) in r.trustee_public_keys.iter().enumerate() {
        let mut errs = errs.scope(&format!("trustee public key #{}", i));
        errs.check(BigUint::from(tpk.coefficients.len()) == r.parameters.threshold,
            "wrong number of coefficients");

        for (j, tc) in tpk.coefficients.iter().enumerate() {
            let mut errs = errs.scope(&format!("coefficient #{}", j));
            // Note: this check uses the base hash, not the extended base hash.  The extended hash
            // isn't computed until after the trustee keys have been generated.
            errs.check(tc.proof.check(
                &tc.public_key,
                |key, comm| hash_uee(&r.base_hash, key, comm),
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
            if let Some(ct) = errs.check_get(&r.contest_tallies, j) {
                errs.check(cc.selections.len() == ct.selections.len(),
                    "wrong number of selections for contest");
            }
            errs.check(cc.max_selections == BigUint::one(),
                "max_selections is not 1");

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
            if let Some(ct) = errs.check_get(&r.contest_tallies, j) {
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

    errs.check(dv.decrypted_value ==
        &dv.encrypted_value.ciphertext / &compute_share_product(&dv.shares),
        "decrypted value was not computed correctly");

    for (i, s) in dv.shares.iter().enumerate() {
        if let Some(ref proof) = s.proof {
            errs.check(s.recovery.is_none(),
                "decrypted value has both proof and recovery fragments");

            if let Some(tpk) = errs.check_get(&r.trustee_public_keys, i) {
                if let Some(c) = errs.check_get(&tpk.coefficients, 0) {
                    errs.check(proof.check_exp(
                        &c.public_key,
                        &dv.encrypted_value.public_key,
                        &s.share,
                        |msg, comm| hash_umc(&r.extended_base_hash, msg, comm),
                    ).is_ok(), "invalid Chaum-Pedersen proof of correct share computation");
                }
            }
        } else if let Some(ref sr) = s.recovery {
            for (j, f) in sr.fragments.iter().enumerate() {
                let mut errs = errs.scope(&format!("recovery fragment #{}", j));

                errs.check(f.trustee_index >= BigUint::one() &&
                    f.trustee_index <= r.parameters.num_trustees,
                    "trustee index is out of range");

                errs.check(f.lagrange_coefficient ==
                    compute_lagrange_coefficient(&sr.fragments, j),
                    "Lagrange coefficient was computed incorrectly");

                if let Some(tpk) = errs.check_get(&r.trustee_public_keys, i) {
                    // TODO: Replace with the proper public key corresponding to Pil.
                    let K_recovery = Element::one();
                    // TODO: this check is expected to fail until the above TODO is fixed
                    errs.check(f.proof.check_exp(
                        &K_recovery,
                        &dv.encrypted_value.public_key,
                        &f.fragment,
                        |msg, comm| hash_umc(&r.extended_base_hash, msg, comm),
                    ).is_ok(), "invalid Chaum-Pedersen proof of correct fragment computation");
                }
            }

            errs.check(s.share == compute_reassembled_share(&sr.fragments),
                "reassembly of share from fragments was not computed correctly");
        } else {
            errs.check(false, "decrypted value has neither proof nor recovery fragments");
        }
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

/// Compute the decrypted version of `message.ciphertext`, using the product of the `shares`.
pub fn compute_share_product(
    shares: &[Share],
) -> Element {
    let mut product = Element::one();
    for s in shares {
        product = &product * &s.share;
    }
    product
}

pub fn compute_lagrange_coefficient(
    fragments: &[Fragment],
    // The index of the fragment whose Lagrange coefficient we are computing.
    index: usize,
) -> Coefficient {
    let mut numerator = Coefficient::one();
    let mut denominator = Coefficient::one();

    let l = Coefficient::new(fragments[index].trustee_index.clone());
    for (i, f) in fragments.iter().enumerate() {
        if i == index {
            continue;
        }
        let j = Coefficient::new(f.trustee_index.clone());
        numerator = &numerator * &j;
        denominator = &denominator * &(&j - &l);
    }

    numerator / denominator
}

pub fn compute_reassembled_share(
    fragments: &[Fragment],
) -> Element {
    let mut product = Element::one();
    for f in fragments {
        product = &product * &f.fragment.pow(&f.lagrange_coefficient.to_exponent());
    }
    product
}
