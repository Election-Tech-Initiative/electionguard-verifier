use num::BigUint;

use crate::crypto::elgamal::Group;

pub mod public_key;

use crate::crypto::schnorr;
use public_key::PublicKey;

#[derive(Debug)]
pub struct Error {
    key_index: u32,
    error: schnorr::Error,
}

pub fn check_keys<'a>(
    keys: &'a [PublicKey],
    group: &'a Group,
    extended_base_hash: &'a BigUint,
) -> impl Iterator<Item = Error> + 'a {
    keys.into_iter()
        .map(move |key| key.check(group, extended_base_hash))
        .enumerate()
        .flat_map(|(i, errors)| errors.map(move |e| (i, e)))
        .map(|(i, error)| Error {
            key_index: i as u32,
            error,
        })
}
