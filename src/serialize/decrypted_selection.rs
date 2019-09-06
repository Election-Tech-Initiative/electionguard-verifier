use num::{BigUint, Num};
use serde::{ser, Serialize, Serializer, de, Deserialize, Deserializer};
use serde::ser::SerializeStruct;
use crate::schema::DecryptedValue;

pub fn serialize<S>(value: &DecryptedValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("DecryptedValue", 4)?;
    state.serialize_field("cleartext", &value.cleartext)?;
    state.serialize_field("decrypted_message", &value.decrypted_value)?;
    state.serialize_field("encrypted_message", &value.encrypted_value)?;
    state.serialize_field("shares", &value.shares)?;
    state.end()
}
