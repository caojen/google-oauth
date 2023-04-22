use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Certs {
    pub keys: Vec<Cert>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cert {
    pub kid: String,
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub n: String,
}
