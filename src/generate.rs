use num::{BigUint, ToPrimitive};
use num::bigint::RandomBits;
use num::traits::{Zero, One, Pow};
use rand::Rng;

use crate::crypto::group::{Element, Exponent, generator, prime, prime_minus_one};
use crate::crypto::elgamal::Message;
use crate::crypto::schnorr;
use crate::crypto::chaum_pederson;
use crate::crypto::hash::{hash_uee, hash_umc, hash_umcc};
use crate::ballot;
use crate::schema;
use crate::check;


pub struct Ballot {
    pub information: ballot::Information,
    pub contests: Vec<Contest>,
}

pub struct Contest {
    pub selections: Vec<bool>,
}

pub struct Election {
    pub parameters: schema::Parameters,
    pub cast_ballots: Vec<Ballot>,
    pub spoiled_ballots: Vec<Ballot>,
}

#[derive(Clone, Default)]
pub struct TrusteeSecrets {
    pub secret_keys: Vec<Exponent>,
    pub shares: Vec<Element>,
}


pub fn generate(rng: &mut impl Rng, e: Election) -> schema::Record {
    let threshold = e.parameters.threshold.to_usize().unwrap();
    let num_trustees = e.parameters.num_trustees.to_usize().unwrap();
    let g = generator();

    let base_hash = check::compute_base_hash(&e.parameters);

    let trustee_secrets = generate_trustee_secrets(rng, num_trustees, threshold);
    let trustee_public_keys = generate_trustee_public_keys(rng, &base_hash, &trustee_secrets);

    let joint_public_key = check::compute_joint_public_key(&trustee_public_keys);

    let extended_base_hash = check::compute_extended_base_hash(&base_hash, &trustee_public_keys);

    let cast_ballots = e.cast_ballots.iter().map(|b| generate_cast_ballot(
        rng,
        &joint_public_key,
        &extended_base_hash,
        b,
    )).collect::<Vec<_>>();

    let contest_tallies = generate_contest_tallies(
        rng,
        &trustee_secrets,
        &extended_base_hash,
        &cast_ballots,
    );

    let spoiled_ballots = e.spoiled_ballots.iter().map(|b| generate_spoiled_ballot(
        rng,
        &trustee_secrets,
        &joint_public_key,
        &extended_base_hash,
        b,
    )).collect::<Vec<_>>();

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

    // The secret keys are generated as Elements (for use as polynomial coefficients), then
    // converted to Exponents (for use in encryption).
    let mut coefficients = vec![Vec::with_capacity(threshold); num_trustees];

    // Generate secret coefficients
    for i in 0 .. num_trustees {
        for _ in 0 .. threshold {
            let coefficient = random_element(rng);
            secrets[i].secret_keys.push(Exponent::new(coefficient.as_uint().clone()));
            coefficients[i].push(coefficient);
        }
    }

    // Distribute key shares to other trustees.  In a full implementation, this step would be more
    // complicated: trustees have to distribute the shares via private channels, and the have to
    // validate each share that they receive from other trustees.
    for i in 0 .. num_trustees {
        for l in 0 .. num_trustees {
            // The argument to the polynomial is the 1-based index of the trustee receiving the
            // share.
            let x = Element::new(BigUint::from(l + 1));

            let mut Pil = BigUint::zero();
            // We do this arithmetic on raw BigUints.  The polynomial involves addition, which is
            // not a supported operation for elements of the multiplicative group.
            for j in 0 .. threshold {
                let a = &coefficients[i][j] * &x.pow(&BigUint::from(j));
                Pil += a.as_uint();
            }

            secrets[l].shares.push(Element::new(Pil));
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
            let proof = schnorr::Proof::prove(
                &public_key,
                s,
                &random_exponent(rng),
                |key, comm| hash_uee(&base_hash, key, comm),
            );

            coefficients.push(schema::TrusteeCoefficient {
                public_key,
                proof,
            });
        }

        public_keys.push(schema::TrusteePublicKey {
            coefficients,
        });
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
            let message = Message::encrypt(
                joint_public_key,
                &cleartext, 
                &one_time_secret,
            );

            let proof = if s {
                chaum_pederson::disj::Proof::prove_one(
                    joint_public_key,
                    &message,
                    &one_time_secret,
                    &random_exponent(rng),
                    &random_exponent(rng),
                    &random_exponent(rng),
                    |msg, comm0, comm1| hash_umcc(extended_base_hash, msg, comm0, comm1),
                )
            } else {
                chaum_pederson::disj::Proof::prove_zero(
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

            selections.push(schema::CastSelection {
                message,
                proof,
            });
        }

        let selection_sum = check::compute_selection_sum(&selections);
        let mut selection_sum_secret = Exponent::zero();
        for ss in &selection_secrets {
            selection_sum_secret = &selection_sum_secret + ss;
        }

        // TODO: currently hardcoded
        let max_selections = BigUint::one();
        let num_selections_proof = chaum_pederson::Proof::prove_plaintext(
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
    trustee_secrets: &[TrusteeSecrets],
    extended_base_hash: &BigUint,
    cast_ballots: &[schema::CastBallot],
) -> Vec<schema::ContestTally> {
    if cast_ballots.len() == 0 {
        return Vec::new();
    }

    // Get the ballot structure from the first ballot.
    let contest_selections = cast_ballots[0].contests.iter()
        .map(|c| c.selections.len()).collect::<Vec<_>>();

    // Add up encrypted ballots and decrypt the tallies
    let mut contests = Vec::with_capacity(contest_selections.len());
    for i in 0 .. contest_selections.len() {
        let mut selections = Vec::with_capacity(contest_selections[i]);
        for j in 0 .. contest_selections[i] {
            let tally = check::compute_encrypted_tally(cast_ballots, i, j);
            let value = generate_decrypted_value(
                rng,
                trustee_secrets,
                extended_base_hash,
                tally,
            );
            selections.push(schema::SelectionTally {
                value,
            });
        }
        contests.push(schema::ContestTally {
            selections,
        });
    }

    contests
}

pub fn generate_spoiled_ballot(
    rng: &mut impl Rng,
    trustee_secrets: &[TrusteeSecrets],
    joint_public_key: &Element,
    extended_base_hash: &BigUint,
    b: &Ballot,
) -> schema::SpoiledBallot {
    let cast = generate_cast_ballot(rng, joint_public_key, extended_base_hash, b);

    let mut contests = Vec::with_capacity(cast.contests.len());
    for c in cast.contests {
        let mut selections = Vec::with_capacity(c.selections.len());
        for s in c.selections {
            let value = generate_decrypted_value(
                rng,
                trustee_secrets,
                extended_base_hash,
                s.message,
            );
            selections.push(schema::SpoiledSelection {
                value,
            });
        }
        contests.push(schema::SpoiledContest {
            selections,
        });
    }

    schema::SpoiledBallot {
        ballot_info: cast.ballot_info,
        contests,
    }
}

pub fn generate_decrypted_value(
    rng: &mut impl Rng,
    trustee_secrets: &[TrusteeSecrets],
    extended_base_hash: &BigUint,
    message: Message,
) -> schema::DecryptedValue {
    // TODO
    schema::DecryptedValue {
        cleartext: BigUint::zero(),
        decrypted_value: Element::one(),
        encrypted_value: message,
        shares: Vec::new(),
    }
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
    let p1 = prime_minus_one();
    loop {
        let x = rng.sample(RandomBits::new(p1.bits()));
        if &x < p1 {
            return Exponent::new(x);
        }
    }
}
