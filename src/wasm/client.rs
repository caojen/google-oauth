#![allow(non_upper_case_globals)]

use std::sync::Arc;
use std::time;
use async_rwlock::RwLock;
use wasm_bindgen::prelude::*;
use crate::{Cert, Certs, GOOGLE_OAUTH_V3_USER_INFO_API, GOOGLE_SA_CERTS_URL, GoogleAccessTokenPayload, GooglePayload, utils};
use anyhow::bail;
use lazy_static::lazy_static;
use crate::jwt_parser::JwtParser;
use crate::validate::id_token;

lazy_static! {
    static ref ca: reqwest::Client = reqwest::Client::new();
}

#[derive(Debug)]
#[wasm_bindgen(getter_with_clone)]
pub struct Client {
    client_id: String,
    cached_certs: Arc<RwLock<Certs>>
}

#[wasm_bindgen]
impl Client {
    #[wasm_bindgen(constructor)]
    pub fn new(client_id: String) -> Client {
        Client {
            client_id,
            cached_certs: Arc::default(),
        }
    }

    #[wasm_bindgen]
    pub async fn validate_id_token(&self, token: String) -> Result<GooglePayload, String> {
        let parser: JwtParser<GooglePayload> = match JwtParser::parse(&token) {
            Ok(jwt) => jwt,
            Err(e) => return Err(format!("{:?}", e)),
        };

        if let Err(e) = id_token::validate_info(&self.client_id, &parser) {
            return Err(format!("{:?}", e));
        }

        let cert = match self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str()).await {
            Ok(cert) => cert,
            Err(e) => return Err(format!("{:?}", e))
        };

        if let Err(e) = id_token::do_validate(&cert, &parser) {
            return Err(format!("{:?}", e));
        }

        Ok(parser.payload)
    }

    async fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        {
            let cached_certs = self.cached_certs.read().await;
            if !cached_certs.need_refresh() {
                return match cached_certs.find_cert(alg, kid) {
                    Ok(cert) => Ok(cert),
                    Err(e) => bail!("{}", e),
                };
            }
        }

        let mut cached_certs = self.cached_certs.write().await;

        let resp = ca.get(GOOGLE_SA_CERTS_URL)
            .send()
            .await?;

        let max_age = utils::parse_max_age_from_async_resp(&resp);
        let text = resp.text().await?;

        *cached_certs = serde_json::from_str(&text)?;
        cached_certs.set_cache_until((time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs() + max_age) as u32);

        return match cached_certs.find_cert(alg, kid) {
            Ok(cert) => Ok(cert),
            Err(e) => bail!("{}", e),
        }
    }

    #[wasm_bindgen]
    pub async fn validate_access_token(&self, token: String) -> Result<GoogleAccessTokenPayload, String> {
        match self.do_validate_access_token(token.as_str()).await {
            Ok(ret) => Ok(ret),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    async fn do_validate_access_token(&self, token: &str) -> anyhow::Result<GoogleAccessTokenPayload> {
        let url = format!("{}?access_token={}", GOOGLE_OAUTH_V3_USER_INFO_API, token);

        let info = ca.get(url)
            .send()
            .await?
            .text()
            .await?;

        let payload = serde_json::from_str(&info)?;

        Ok(payload)
    }
}
