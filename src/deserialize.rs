use num::BigUint;
use serde::{Deserialize, Deserializer};

pub fn biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let n: u64 = Deserialize::deserialize(deserializer)?;
    Ok(From::from(n))
}
