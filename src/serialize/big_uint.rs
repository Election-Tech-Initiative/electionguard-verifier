use num::{BigUint, Num};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize)]
#[serde(transparent)]
pub struct SerializeBigUint<'a>(#[serde(serialize_with = "self::serialize")] pub &'a BigUint);

pub fn serialize<S>(value: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.to_str_radix(10).serialize(serializer)
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StringOrUint {
    String(String),
    Uint(u64),
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let su: StringOrUint = Deserialize::deserialize(deserializer)?;
    match su {
        StringOrUint::String(s) => BigUint::from_str_radix(&s, 10).map_err(de::Error::custom),
        StringOrUint::Uint(u) => Ok(BigUint::from(u)),
    }
}
