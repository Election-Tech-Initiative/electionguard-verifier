use serde::Deserialize;

mod selection;

use crate::election::{Hash, Parameters};

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptedBallot {
    selections: Vec<selection::Committment>,
}

#[derive(Debug, Clone)]
pub enum Error {
    Selection { index: u32, error: selection::Error },
}

impl EncryptedBallot {
    pub fn verify(self: &Self, params: &Parameters, extended_base_hash: &Hash) -> Vec<Error> {
        self.selections
            .iter()
            .flat_map(|selection| selection.verify(params, extended_base_hash))
            .enumerate()
            .map(|(i, error)| Error::Selection {
                index: i as u32,
                error,
            })
            .collect()
    }
}
