use chrono::NaiveDate;
use num::bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Location(String);

/// The parameters necessary to carry out an election
#[derive(Deserialize)]
pub struct Parameters {
    /// The data on which the election takes place
    pub date: NaiveDate,
    pub location: Location,
    /// The prime safe prime `p`
    pub prime: BigUint,
    /// The group generator `g`
    pub generator: BigUint,
    /// The total number of trustees `n`
    pub num_trustees: BigUint,
    /// The minimum number of trustees necessary for decryption `k`
    pub threshold: BigUint,
}
