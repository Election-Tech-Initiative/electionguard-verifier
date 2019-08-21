use num::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::elgamal::{Group, Message};
use crate::crypto::hash::Spec;

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "zero_proof")]
    left: super::Proof,
    #[serde(rename = "one_proof")]
    right: super::Proof,
}

#[derive(Debug, Serialize)]
pub struct Status {
    challenge: bool,
    response_left: super::ResponseStatus,
    response_right: super::ResponseStatus,
}

#[derive(Debug, Copy, Clone)]
pub enum HashInput {
    Left(super::HashInput),
    Right(super::HashInput),
}

impl Proof {
    pub fn check(
        &self,
        group: &Group,
        message: &Message,
        public_key: &BigUint,
        spec: Spec<HashInput>,
    ) -> Status {
        Status {
            challenge: self.is_challenge_ok(group, spec),
            response_left: self.left.check_response(group, message, public_key),
            response_right: self.right.check_response(group, message, public_key),
        }
    }

    fn is_challenge_ok(&self, group: &Group, spec: Spec<HashInput>) -> bool {
        let Group { prime: p, .. } = group;

        let expected = spec.exec::<_, Sha256>(|x| match x {
            HashInput::Left(x) => &self.left.resolver()(x),
            HashInput::Right(x) => &self.right.resolver()(x),
        });

        expected == (&self.left.challenge + &self.right.challenge) % (p - 1u8)
    }
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.challenge && self.response_left.is_ok() && self.response_right.is_ok()
    }
}
