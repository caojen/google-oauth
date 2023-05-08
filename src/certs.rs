use anyhow::bail;
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

pub fn find_cert(certs: Vec<Cert>, alg: &str, kid: &str) -> anyhow::Result<Cert> {
    match certs.iter().find(|cert| cert.alg == alg && cert.kid == kid) {
        Some(cert) => Ok(cert.clone()),
        None => bail!("alg {}, kid = {} not found in google certs", alg, kid),
    }
}
