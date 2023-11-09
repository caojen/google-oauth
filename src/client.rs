#![allow(non_upper_case_globals)]

use std::ops::Add;
use std::sync::{Arc, RwLock};
use lazy_static::lazy_static;
use crate::{DEFAULT_TIMEOUT, GOOGLE_OAUTH_V3_USER_INFO_API, GOOGLE_SA_CERTS_URL, GoogleAccessTokenPayload, GooglePayload, utils};
use std::time::{Duration, Instant};
use log::debug;
use crate::certs::{Cert, Certs};
use crate::jwt_parser::JwtParser;
use crate::validate::id_token;

lazy_static! {
    static ref cb: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

/// Client is a blocking client to do verification.
#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
    timeout: Duration,
    cached_certs: Arc<RwLock<Certs>>,
}

impl Client {
    /// Create a new blocking client.
    pub fn new<S: ToString>(client_id: S) -> Self {
        Self {
            client_id: client_id.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT),
            cached_certs: Arc::default(),
        }
    }

    /// Set the timeout (which is used in fetching google certs).
    /// Default timeout is 5 seconds. Zero timeout will be ignored.
    pub fn timeout(mut self, d: Duration) -> Self {
        if d.as_nanos() != 0 {
            self.timeout = d;
        }

        self
    }

    /// Do verification with `id_token`. If succeed, return the user data.
    pub fn validate_id_token<S>(&self, token: S) -> anyhow::Result<GooglePayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(token)?;

        id_token::validate_info(&self.client_id, &parser)?;

        let cert = self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str())?;

        id_token::do_validate(&cert, &parser)?;

        Ok(parser.payload)
    }

    fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        {
            let cached_certs = self.cached_certs.read().unwrap();
            if !cached_certs.need_refresh() {
                debug!("certs: use cache");
                return cached_certs.find_cert(alg, kid);
            }
        }

        debug!("certs: try to fetch new certs");

        let mut cached_certs = self.cached_certs.write().unwrap();

        // we need to refresh certs here...
        let resp = cb.get(GOOGLE_SA_CERTS_URL)
            .timeout(self.timeout)
            .send()?;

        // parse the response header `max-age`.
        let max_age = utils::parse_max_age_from_resp(&resp);

        let text = resp.text()?;
        *cached_certs = serde_json::from_str(&text)?;

        cached_certs.set_cache_until(
            Instant::now().add(Duration::from_secs(max_age))
        );

        cached_certs.find_cert(alg, kid)
    }

    /// Try to validate access token. If succeed, return the user info.
    pub fn validate_access_token<S>(&self, token: S) -> anyhow::Result<GoogleAccessTokenPayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        let info = cb.get(format!("{}?access_token={}", GOOGLE_OAUTH_V3_USER_INFO_API, token))
            .timeout(self.timeout)
            .send()?
            .text()?;

        let payload = serde_json::from_str(&info)?;

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_id_token() {
        env_logger::try_init().unwrap_or_default();

        let client = Client::new("1012916199183-mokbc9qrmssv8e1odemhv723jnaugcfk.apps.googleusercontent.com");
        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6ImY1ZjRiZjQ2ZTUyYjMxZDliNjI0OWY3MzA5YWQwMzM4NDAwNjgwY2QiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDEyOTE2MTk5MTgzLW1va2JjOXFybXNzdjhlMW9kZW1odjcyM2puYXVnY2ZrLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNzE0OTU2NDQ2NTYwNzkyNzU2OCIsImVtYWlsIjoibmV0aWQuY2FvamVuQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE2OTk1MTYzMzgsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lnUWlYQmg3ZG9TUV9DN25QZlJvUWdPc2h2WHpJaURFV2xESW1nWF9UTEt3PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwibG9jYWxlIjoiemgtQ04iLCJpYXQiOjE2OTk1MTY2MzgsImV4cCI6MTY5OTUyMDIzOCwianRpIjoiYjdkY2UzNjIwYzQ4N2RhY2UzOWRmOTU3OTAwNjVkMjNiNmIzYWVkZSJ9.EHO2t2OZw_4Y22gXIGqeusV0WOlbfl4omDdqJ9WexkCtM2dyG9y8mWXucyKI7QFAibGg7dEs380e_wUDU4x9JiUSCrDFFaQFVStgcBTHmjEf2Gw1uAo9nY1WKw6-FymzUIYWPydMmAaFPcF_OgO1LY2MAKFyw_L-Y_7EQpgeutII1SmT1jiWG3Kewrshvb49AzJX1k-wUhd5LGjfoNkepdEZF45d3_XosHTaBX5euYvo7RdpBeznTbaqBTCRqBerruCyS60Mxg8b_If0bNMFSx1oKir3d6BYrgGvNtGh_J544Pk8WO77Q_zs4AXro_c2ID7ABknYj3MsXaWrdytaOQ");
        data.unwrap();

        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6ImY1ZjRiZjQ2ZTUyYjMxZDliNjI0OWY3MzA5YWQwMzM4NDAwNjgwY2QiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDEyOTE2MTk5MTgzLW1va2JjOXFybXNzdjhlMW9kZW1odjcyM2puYXVnY2ZrLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNzE0OTU2NDQ2NTYwNzkyNzU2OCIsImVtYWlsIjoibmV0aWQuY2FvamVuQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE2OTk1MTYzMzgsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lnUWlYQmg3ZG9TUV9DN25QZlJvUWdPc2h2WHpJaURFV2xESW1nWF9UTEt3PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwibG9jYWxlIjoiemgtQ04iLCJpYXQiOjE2OTk1MTY2MzgsImV4cCI6MTY5OTUyMDIzOCwianRpIjoiYjdkY2UzNjIwYzQ4N2RhY2UzOWRmOTU3OTAwNjVkMjNiNmIzYWVkZSJ9.EHO2t2OZw_4Y22gXIGqeusV0WOlbfl4omDdqJ9WexkCtM2dyG9y8mWXucyKI7QFAibGg7dEs380e_wUDU4x9JiUSCrDFFaQFVStgcBTHmjEf2Gw1uAo9nY1WKw6-FymzUIYWPydMmAaFPcF_OgO1LY2MAKFyw_L-Y_7EQpgeutII1SmT1jiWG3Kewrshvb49AzJX1k-wUhd5LGjfoNkepdEZF45d3_XosHTaBX5euYvo7RdpBeznTbaqBTCRqBerruCyS60Mxg8b_If0bNMFSx1oKir3d6BYrgGvNtGh_J544Pk8WO77Q_zs4AXro_c2ID7ABknYj3MsXaWrdytaOQ");
        data.unwrap();
    }

    #[test]
    fn verify_access_token() {
        let client = Client::new("525360879715-3kfn0tge3t1nouvk9ol5jgaiv2rtp0s9.apps.googleusercontent.com");
        let token = "ya29.a0AfB_byCH_ODaYF16gXLDn7yO6M6En58FEyBfWeentCVJ664dy6ASRYDfVcYoN4qDDjWwFl7_9R6deSPndy8ZZf1sO5X078pqY5oH4bDbydc-v3Ulux_LeIhWZQQybfjJKdFGjmLaWGxOfYaiKhJGOFFzxI41XuX8FX9waCgYKAfMSARISFQGOcNnCqo7b7NhcUZjGUK6B9su5vw0171";

        let payload = client.validate_access_token(token);
        payload.unwrap();
    }
}
