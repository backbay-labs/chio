use alloc::string::String;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMutationFence {
    pub store_uuid: String,
    pub lease_id: String,
    pub owner_epoch: u64,
}
