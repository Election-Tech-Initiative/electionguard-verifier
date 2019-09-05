use serde::{Deserialize, Serialize};

/// Auxiliary information about a ballot other than the selections made by the voter.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Information {
    /// The date the ballot was encrypted.
    date: String,

    /// Information about the device that encrypted the ballot
    device_info: String,

    /// The time the ballot was encrypted.
    time: String,

    /// The tracker code generated for this ballot.
    tracker: String,
}
