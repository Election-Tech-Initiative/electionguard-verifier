use num::BigUint;

use crate::crypto::elgamal::Group;

pub mod public_key;

use public_key::PublicKey;

#[derive(Debug)]
pub struct Error {
    key_index: u32,
    error: public_key::Error,
}

pub fn verify_keys<'a>(
    keys: &'a [PublicKey],
    group: &'a Group,
    extended_base_hash: &'a BigUint,
) -> impl Iterator<Item = Error> + 'a {
    keys.into_iter()
        .map(move |key| key.verify(group, extended_base_hash))
        .enumerate()
        .flat_map(|(i, errors)| {
            errors.map(move |e| Error {
                key_index: i as u32,
                error: e,
            })
        })
}
