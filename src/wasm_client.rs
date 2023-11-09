use wasm_bindgen::prelude::wasm_bindgen;
use crate::certs::Certs;


#[derive(Debug, Clone)]
#[wasm_bindgen]
pub struct Client {
    client_id: String,
    certs: Certs,
}

pub type AsyncClient = Client;

impl Client {
    pub fn new(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            certs: Default::default(),
        }
    }
}
