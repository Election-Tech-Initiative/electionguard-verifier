use num::{BigUint, FromPrimitive};
use serde::{de, Deserialize, Deserializer};

pub fn biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let n = <u128 as Deserialize>::deserialize(deserializer)?;
    BigUint::from_u128(n).ok_or(de::Error::custom("Unable to serialize BigUint from value"))
}
