use num::{BigUint, Num};
use serde::{ser, Serialize, Serializer, de, Deserialize, Deserializer};

pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.to_str_radix(16).serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    BigUint::from_str_radix(&s, 16).map_err(de::Error::custom)
}


