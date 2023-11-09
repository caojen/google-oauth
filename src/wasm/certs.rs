use std::time;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize, Deserialize, Debug, Default)]
#[wasm_bindgen(getter_with_clone)]
pub struct Certs {
    keys: Vec<Cert>,

    #[serde(skip)]
    /// MUST refresh certs from Google server again, when current_timestamp > cache_until
    cache_until: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[wasm_bindgen(getter_with_clone)]
pub struct Cert {
    pub kid: String,
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub n: String,
}

#[wasm_bindgen]
impl Certs {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Certs {
        Default::default()
    }

    #[wasm_bindgen]
    pub fn find_cert(&self, alg: &str, kid: &str) -> Result<Cert, String> {
        match self.keys.iter().find(|cert| cert.alg == alg && cert.kid == kid) {
            Some(cert) => Ok(cert.clone()),
            None => Err(format!("cert: alg {}, kid = {} not found in google certs", alg, kid)),
        }
    }

    #[wasm_bindgen]
    pub fn need_refresh(&self) -> bool {
        self.cache_until as u64 > time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs()
    }

    pub fn set_cache_until(&mut self, cache_until: u32) {
        self.cache_until = cache_until;
    }
}
