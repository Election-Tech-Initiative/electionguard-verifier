use num::bigint::RandomBits;
use num::traits::{One, Pow, Zero};
use num::{BigUint, ToPrimitive};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::check;
use crate::crypto::chaum_pedersen;
use crate::crypto::elgamal::Message;
use crate::crypto::group::{
    generator, prime_minus_one, subgroup_prime, Coefficient, Element, Exponent,
};
use crate::crypto::hash::{hash_uee, hash_umc, hash_umcc};
use crate::crypto::schnorr;
use crate::schema;

#[derive(Serialize, Deserialize)]
pub struct Ballot {
    pub information: schema::BallotInfo,
    pub contests: Vec<Contest>,
}

#[derive(Serialize, Deserialize)]
pub struct Contest {
    pub selections: Vec<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct Election {
    pub parameters: schema::Parameters,
    pub cast_ballots: Vec<Ballot>,
    pub spoiled_ballots: Vec<Ballot>,
    /// Indicates which of the trustees should be considered present at decryption time.
    pub trustees_present: Vec<bool>,
}

#[derive(Clone, Default)]
pub struct TrusteeSecrets {
    secret_keys: Vec<Exponent>,
    shares: Vec<Coefficient>,
}

pub struct TrusteeInfo<'a> {
    num: usize,
    threshold: usize,
    secrets: &'a [TrusteeSecrets],
    public_keys: &'a [schema::TrusteePublicKey],
    present: &'a [bool],
}

pub fn generate(rng: &mut impl Rng, e: Election) -> schema::Record {
    let threshold = e.parameters.threshold.to_usize().unwrap();
    let num_trustees = e.parameters.num_trustees.to_usize().unwrap();

    // Setup phase

    let base_hash = check::compute_base_hash(&e.parameters);

    let trustee_secrets = generate_trustee_secrets(rng, num_trustees, threshold);
    let trustee_public_keys = generate_trustee_public_keys(rng, &base_hash, &trustee_secrets);

    let joint_public_key = check::compute_joint_public_key(&trustee_public_keys);

    let extended_base_hash = check::compute_extended_base_hash(&base_hash, &trustee_public_keys);

    // Voting phase

    let cast_ballots = e
        .cast_ballots
        .iter()
        .map(|b| generate_cast_ballot(rng, &joint_public_key, &extended_base_hash, b))
        .collect::<Vec<_>>();

    // A `CastBallot` for each spoiled ballot.  These will be turned into `SpoiledBallots` during
    // decryption.
    let spoiled_cast_ballots = e
        .spoiled_ballots
        .iter()
        .map(|b| generate_cast_ballot(rng, &joint_public_key, &extended_base_hash, b))
        .collect::<Vec<_>>();

    // Decryption phase

    assert!(e.trustees_present.len() == num_trustees);

    let trustee_info = TrusteeInfo {
        num: num_trustees,
        threshold,
        secrets: &trustee_secrets,
        public_keys: &trustee_public_keys,
        present: &e.trustees_present,
    };

    let contest_tallies =
        generate_contest_tallies(rng, &trustee_info, &extended_base_hash, &cast_ballots);

    compare_decrypted_tallies(&contest_tallies, &e.cast_ballots);

    let spoiled_ballots = spoiled_cast_ballots
        .into_iter()
        .map(|b| generate_spoiled_ballot(rng, &trustee_info, &extended_base_hash, b))
        .collect::<Vec<_>>();

    schema::Record {
        parameters: e.parameters.clone(),
        base_hash,
        trustee_public_keys,
        joint_public_key,
        extended_base_hash,
        cast_ballots,
        contest_tallies,
        spoiled_ballots,
    }
}

fn generate_trustee_secrets(
    rng: &mut impl Rng,
    num_trustees: usize,
    threshold: usize,
) -> Vec<TrusteeSecrets> {
    let mut secrets = vec![TrusteeSecrets::default(); num_trustees];

    // Generate secret coefficients
    for secret in secrets.iter_mut().take(num_trustees) {
        for _ in 0..threshold {
            // Coefficients are in the range 0 < x < p, so we use `random_element` to generate
            // them.
            let aij = Coefficient::from_element(random_element(rng));
            secret.secret_keys.push(aij.to_exponent());
        }
    }

    // Distribute key shares to other trustees.  In a full implementation, this step would be more
    // complicated: trustees have to distribute the shares via private channels, and the have to
    // validate each share that they receive from other trustees.
    for i in 0..num_trustees {
        for idx in 0..num_trustees {
            // The argument to the polynomial is the 1-based index of the trustee receiving the
            // share.
            let l = Coefficient::from(idx as u32 + 1);

            let mut Pil = Coefficient::zero();
            for j in 0..threshold {
                let aij = Coefficient::from_exponent(secrets[i].secret_keys[j].clone());
                let a = &aij * &l.pow(&BigUint::from(j));
                Pil = Pil + a;
            }

            secrets[idx].shares.push(Pil);
        }
    }

    secrets
}

pub fn generate_trustee_public_keys(
    rng: &mut impl Rng,
    base_hash: &BigUint,
    trustee_secrets: &[TrusteeSecrets],
) -> Vec<schema::TrusteePublicKey> {
    let num_trustees = trustee_secrets.len();
    let mut public_keys = Vec::with_capacity(num_trustees);

    for ts in trustee_secrets {
        let mut coefficients = Vec::with_capacity(num_trustees);

        for s in &ts.secret_keys {
            let public_key = generator().pow(s);
            let proof =
                schnorr::Proof::prove(&public_key, s, &random_exponent(rng), |key, comm| {
                    hash_uee(&base_hash, key, comm)
                });

            coefficients.push(schema::TrusteeCoefficient { public_key, proof });
        }

        public_keys.push(schema::TrusteePublicKey { coefficients });
    }

    public_keys
}

pub fn generate_cast_ballot(
    rng: &mut impl Rng,
    joint_public_key: &Element,
    extended_base_hash: &BigUint,
    b: &Ballot,
) -> schema::CastBallot {
    let mut contests = Vec::with_capacity(b.contests.len());
    for c in &b.contests {
        let mut selections = Vec::with_capacity(c.selections.len());
        let mut selection_secrets = Vec::new();

        for &s in &c.selections {
            let cleartext = if s { BigUint::one() } else { BigUint::zero() };

            let one_time_secret = random_exponent(rng);
            let message = Message::encrypt(joint_public_key, &cleartext, &one_time_secret);

            let proof = if s {
                chaum_pedersen::disj::Proof::prove_one(
                    joint_public_key,
                    &message,
                    &one_time_secret,
                    &random_exponent(rng),
                    &random_exponent(rng),
                    &random_exponent(rng),
                    |msg, comm0, comm1| hash_umcc(extended_base_hash, msg, comm0, comm1),
                )
            } else {
                chaum_pedersen::disj::Proof::prove_zero(
                    joint_public_key,
                    &message,
                    &one_time_secret,
                    &random_exponent(rng),
                    &random_exponent(rng),
                    &random_exponent(rng),
                    |msg, comm0, comm1| hash_umcc(extended_base_hash, msg, comm0, comm1),
                )
            };

            selection_secrets.push(one_time_secret);

            selections.push(schema::CastSelection { message, proof });
        }

        let selection_sum = check::compute_selection_sum(&selections);
        let mut selection_sum_secret = Exponent::zero();
        for ss in &selection_secrets {
            selection_sum_secret = &selection_sum_secret + ss;
        }

        // TODO: max_selections is currently hardcoded
        let max_selections = BigUint::one();
        let num_selections_proof = chaum_pedersen::Proof::prove_plaintext(
            joint_public_key,
            &selection_sum,
            &selection_sum_secret,
            &max_selections,
            &random_exponent(rng),
            |msg, comm| hash_umc(extended_base_hash, msg, comm),
        );

        contests.push(schema::CastContest {
            selections,
            max_selections,
            num_selections_proof,
        });
    }

    schema::CastBallot {
        ballot_info: b.information.clone(),
        contests,
    }
}

pub fn generate_contest_tallies(
    rng: &mut impl Rng,
    trustee_info: &TrusteeInfo,
    extended_base_hash: &BigUint,
    cast_ballots: &[schema::CastBallot],
) -> Vec<schema::ContestTally> {
    if cast_ballots.is_empty() {
        return Vec::new();
    }

    // Get the ballot structure from the first ballot.
    let contest_selections = cast_ballots[0]
        .contests
        .iter()
        .map(|c| c.selections.len())
        .collect::<Vec<_>>();

    // Add up encrypted ballots and decrypt the tallies
    let mut contests = Vec::with_capacity(contest_selections.len());
    for (i, selection) in contest_selections.iter().enumerate() {
        let mut selections = Vec::with_capacity(*selection);
        for j in 0..contest_selections[i] {
            let tally = check::compute_encrypted_tally(cast_ballots, i, j);
            let value = generate_decrypted_value(rng, trustee_info, extended_base_hash, tally);

            selections.push(schema::SelectionTally { value });
        }
        contests.push(schema::ContestTally { selections });
    }

    contests
}

/// Check that the "selection_tally.value.cleartext` results match the actual sums obtained from
/// the unencrypted ballots.
pub fn compare_decrypted_tallies(
    contest_tallies: &[schema::ContestTally],
    unencrypted_cast_ballots: &[Ballot],
) {
    for (i, contest) in contest_tallies.iter().enumerate() {
        for (j, selection) in contest.selections.iter().enumerate() {
            let unencrypted_tally: BigUint = unencrypted_cast_ballots
                .iter()
                .map(|b| BigUint::from(b.contests[i].selections[j] as u8))
                .sum();
            assert_eq!(unencrypted_tally, selection.value.cleartext);
        }
    }
}

pub fn generate_spoiled_ballot(
    rng: &mut impl Rng,
    trustee_info: &TrusteeInfo,
    extended_base_hash: &BigUint,
    cast: schema::CastBallot,
) -> schema::SpoiledBallot {
    let mut contests = Vec::with_capacity(cast.contests.len());
    for c in cast.contests {
        let mut selections = Vec::with_capacity(c.selections.len());
        for s in c.selections {
            let value = generate_decrypted_value(rng, trustee_info, extended_base_hash, s.message);
            selections.push(schema::SpoiledSelection { value });
        }
        contests.push(schema::SpoiledContest { selections });
    }

    schema::SpoiledBallot {
        ballot_info: cast.ballot_info,
        contests,
    }
}

pub fn generate_decrypted_value(
    rng: &mut impl Rng,
    trustees: &TrusteeInfo,
    extended_base_hash: &BigUint,
    message: Message,
) -> schema::DecryptedValue {
    let num_trustees = trustees.num;

    let mut recovery_trustees = Vec::with_capacity(trustees.threshold);
    for (i, &present) in trustees.present.iter().enumerate() {
        if present && recovery_trustees.len() < trustees.threshold {
            recovery_trustees.push(i);
        }
    }
    assert!(
        recovery_trustees.len() == trustees.threshold,
        "not enough trustees are present for decryption"
    );

    // Build trustee shares M_i
    let mut shares = Vec::with_capacity(num_trustees);
    let A = &message.public_key;
    for i in 0..num_trustees {
        if trustees.present[i] {
            let si = &trustees.secrets[i].secret_keys[0];
            let Mi = A.pow(si);
            let Ki = &trustees.public_keys[i].coefficients[0].public_key;

            let proof = chaum_pedersen::Proof::prove_exp(
                &Ki,
                &si,
                A,
                &Mi,
                &random_exponent(rng),
                |msg, comm| hash_umc(extended_base_hash, msg, comm),
            );

            shares.push(schema::Share {
                recovery: None,
                proof: Some(proof),
                share: Mi,
            });
        } else {
            let mut fragments = Vec::with_capacity(trustees.threshold);
            for &j in &recovery_trustees {
                let l = BigUint::from(j + 1);
                let Pil = trustees.secrets[j].shares[i].to_exponent();
                let Mil = A.pow(&Pil);

                let K_recovery =
                    check::compute_recovery_public_key(&trustees.public_keys[i].coefficients, &l);

                let proof = chaum_pedersen::Proof::prove_exp(
                    &K_recovery,
                    &Pil,
                    A,
                    &Mil,
                    &random_exponent(rng),
                    |msg, comm| hash_umc(extended_base_hash, msg, comm),
                );

                fragments.push(schema::Fragment {
                    fragment: Mil,
                    lagrange_coefficient: Coefficient::zero(),
                    proof,
                    trustee_index: l,
                });
            }

            let mut lagrange_coefficients = Vec::with_capacity(fragments.len());
            for j in 0..fragments.len() {
                lagrange_coefficients.push(check::compute_lagrange_coefficient(&fragments, j));
            }
            for (f, w) in fragments.iter_mut().zip(lagrange_coefficients.into_iter()) {
                f.lagrange_coefficient = w;
            }

            let share = check::compute_reassembled_share(&fragments);

            shares.push(schema::Share {
                recovery: Some(schema::ShareRecovery { fragments }),
                proof: None,
                share,
            })
        }
    }

    let M = &message.ciphertext / &check::compute_share_product(&shares);
    let t = discrete_log(&M).as_uint().clone();

    schema::DecryptedValue {
        cleartext: t,
        decrypted_value: M,
        encrypted_value: message,
        shares,
    }
}

pub fn discrete_log(element: &Element) -> Exponent {
    let g_inv = generator().inverse();

    let mut count = Exponent::zero();
    let mut cur = element.clone();
    while !cur.is_one() {
        cur = &cur * &g_inv;
        count = count + Exponent::one();
    }

    count
}

pub fn random_element(rng: &mut impl Rng) -> Element {
    let p1 = prime_minus_one();
    loop {
        let x: BigUint = rng.sample(RandomBits::new(p1.bits()));
        if &x < p1 {
            return Element::new(x + 1_u8);
        }
    }
}

pub fn random_exponent(rng: &mut impl Rng) -> Exponent {
    let q = subgroup_prime();
    loop {
        let x = rng.sample(RandomBits::new(q.bits()));
        if &x < q {
            return Exponent::new(x);
        }
    }
}
