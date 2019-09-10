use serde::Serializer;
use serde::ser::SerializeStruct;
use crate::schema::DecryptedValue;
use crate::serialize::big_uint::SerializeBigUint;

pub fn serialize<S>(value: &DecryptedValue, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut state = serializer.serialize_struct("DecryptedValue", 4)?;
    state.serialize_field(
        "cleartext",
        &SerializeBigUint(&value.cleartext),
    )?;
    state.serialize_field("decrypted_tally", &value.decrypted_value)?;
    state.serialize_field("encrypted_tally", &value.encrypted_value)?;
    state.serialize_field("shares", &value.shares)?;
    state.end()
}
