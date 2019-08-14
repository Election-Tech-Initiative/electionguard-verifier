use num::{BigUint, Num};
use serde::{de, Deserialize, Deserializer};

pub fn biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let n: u64 = Deserialize::deserialize(deserializer)?;
    Ok(From::from(n))
}

pub fn hash<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    BigUint::from_str_radix(&s, 16).map_err(de::Error::custom)
}
