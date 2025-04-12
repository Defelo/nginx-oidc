use std::{collections::HashMap, ops::Deref};

use openidconnect::AdditionalClaims;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomClaims(HashMap<String, serde_json::Value>);

impl AdditionalClaims for CustomClaims {}

impl Deref for CustomClaims {
    type Target = HashMap<String, serde_json::Value>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
