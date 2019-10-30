use crate::check;
use crate::crypto::group::{generator, prime};
use crate::generate::{self, Ballot, Contest, Election};
use crate::schema::{BallotInfo, Parameters};
use num::BigUint;
use rand;

#[test]
fn test_normal() {
    let dummy_information = BallotInfo {
        date: "today".to_owned(),
        device_info: "this device".to_owned(),
        time: "right now".to_owned(),
        tracker: "123456".to_owned(),
    };

    let e = Election {
        parameters: Parameters {
            location: "right here".to_owned(),
            date: "right now".to_owned(),
            num_trustees: BigUint::from(5_u32),
            threshold: BigUint::from(3_u32),
            prime: prime().clone(),
            generator: generator().clone(),
        },
        cast_ballots: vec![
            Ballot {
                information: dummy_information.clone(),
                contests: vec![
                    Contest {
                        selections: vec![true, false, false],
                    },
                    Contest {
                        selections: vec![false, true, false],
                    },
                    Contest {
                        selections: vec![false, false, true],
                    },
                ],
            },
            Ballot {
                information: dummy_information.clone(),
                contests: vec![
                    Contest {
                        selections: vec![false, true, false],
                    },
                    Contest {
                        selections: vec![false, false, true],
                    },
                    Contest {
                        selections: vec![false, false, true],
                    },
                ],
            },
        ],
        spoiled_ballots: vec![Ballot {
            information: dummy_information.clone(),
            contests: vec![
                Contest {
                    selections: vec![false, false, true],
                },
                Contest {
                    selections: vec![false, true, false],
                },
                Contest {
                    selections: vec![true, false, false],
                },
            ],
        }],
        trustees_present: vec![true, true, true, true, true],
    };

    let record = generate::generate(&mut rand::thread_rng(), e);

    match check::check(&record) {
        Ok(()) => {}
        Err(errs) => {
            for err in &errs {
                eprintln!("{}", err);
            }
            panic!("check failed with {} errors", errs.len());
        }
    }
}

#[test]
// Reconstruction of shares for missing trustees is not fully implemented yet, and may require
// protocol changes.  For now, this test should fail with errors saying "invalid Chaum-Pedersen
// proof of correct fragment computation".
#[should_panic]
fn test_missing() {
    let dummy_information = BallotInfo {
        date: "today".to_owned(),
        device_info: "this device".to_owned(),
        time: "right now".to_owned(),
        tracker: "123456".to_owned(),
    };

    let e = Election {
        parameters: Parameters {
            location: "right here".to_owned(),
            date: "right now".to_owned(),
            num_trustees: BigUint::from(5_u32),
            threshold: BigUint::from(3_u32),
            prime: prime().clone(),
            generator: generator().clone(),
        },
        cast_ballots: vec![
            Ballot {
                information: dummy_information.clone(),
                contests: vec![
                    Contest {
                        selections: vec![true, false, false],
                    },
                    Contest {
                        selections: vec![false, true, false],
                    },
                    Contest {
                        selections: vec![false, false, true],
                    },
                ],
            },
            Ballot {
                information: dummy_information.clone(),
                contests: vec![
                    Contest {
                        selections: vec![false, true, false],
                    },
                    Contest {
                        selections: vec![false, false, true],
                    },
                    Contest {
                        selections: vec![false, false, true],
                    },
                ],
            },
        ],
        spoiled_ballots: vec![Ballot {
            information: dummy_information.clone(),
            contests: vec![
                Contest {
                    selections: vec![false, false, true],
                },
                Contest {
                    selections: vec![false, true, false],
                },
                Contest {
                    selections: vec![true, false, false],
                },
            ],
        }],
        trustees_present: vec![true, true, false, true, true],
    };

    let record = generate::generate(&mut rand::thread_rng(), e);

    match check::check(&record) {
        Ok(()) => {}
        Err(errs) => {
            for err in &errs {
                eprintln!("{}", err);
            }
            panic!("check failed with {} errors", errs.len());
        }
    }
}
