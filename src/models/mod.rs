use rbatis::{crud, rbdc::DateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
    pub created_at: DateTime,
}

crud!(KeyPair {});
