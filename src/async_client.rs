#![allow(non_upper_case_globals)]

use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};
use lazy_static::lazy_static;
use log::debug;
use tokio::sync::RwLock;
use crate::{DEFAULT_TIMEOUT, GOOGLE_OAUTH_V3_USER_INFO_API, GOOGLE_SA_CERTS_URL, GoogleAccessTokenPayload, GooglePayload, utils};
use crate::certs::{Cert, Certs};
use crate::jwt_parser::JwtParser;
use crate::validate::id_token;

lazy_static! {
    static ref ca: reqwest::Client = reqwest::Client::new();
}

/// AsyncClient is an async client to do verification.
#[derive(Debug, Clone)]
pub struct AsyncClient {
    client_id: String,
    timeout: Duration,
    cached_certs: Arc<RwLock<Certs>>,
}

impl AsyncClient {
    /// Create a new async client.
    pub fn new<S: ToString>(client_id: S) -> Self {
        Self {
            client_id: client_id.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT),
            cached_certs: Arc::default(),
        }
    }

    /// Set the timeout (used in fetching google certs).
    /// Default timeout is 5 seconds. Zero timeout will be ignored.
    pub fn timeout(mut self, d: Duration) -> Self {
        if d.as_nanos() != 0 {
            self.timeout = d;
        }

        self
    }

    /// Do verification with `id_token`. If succeed, return the user data.
    pub async fn validate_id_token<S>(&self, token: S) -> anyhow::Result<GooglePayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(token)?;

        id_token::validate_info(&self.client_id, &parser)?;

        let cert = self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str()).await?;

        id_token::do_validate(&cert, &parser)?;

        Ok(parser.payload)
    }

    async fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        {
            let cached_certs = self.cached_certs.read().await;
            if !cached_certs.need_refresh() {
                debug!("certs: use cache");
                return cached_certs.find_cert(alg, kid);
            }
        }

        debug!("certs: try to fetch new certs");

        let mut cached_certs = self.cached_certs.write().await;

        // refresh certs here...
        let resp = ca.get(GOOGLE_SA_CERTS_URL)
            .timeout(self.timeout)
            .send()
            .await?;

        // parse the response header `age` and `max-age`.
        let age = utils::parse_age_from_async_resp(&resp);
        let max_age: u64 = utils::parse_max_age_from_async_resp(&resp);

        let text = resp.text().await?;
        *cached_certs = serde_json::from_str(&text)?;

        let cached_age = if age >= max_age { 0 } else { max_age - age };
        cached_certs.set_cache_until(
            Instant::now().add(Duration::from_secs(cached_age))
        );

        cached_certs.find_cert(alg, kid)
    }

    /// Try to validate access token. If succeed, return the user info.
    pub async fn validate_access_token<S>(&self, token: S) -> anyhow::Result<GoogleAccessTokenPayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        let info = ca.get(format!("{}?access_token={}", GOOGLE_OAUTH_V3_USER_INFO_API, token))
            .timeout(self.timeout)
            .send()
            .await?
            .text()
            .await?;

        let payload = serde_json::from_str(&info)?;

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify() {
        env_logger::try_init().unwrap_or_default();

        let client = AsyncClient::new("1012916199183-mokbc9qrmssv8e1odemhv723jnaugcfk.apps.googleusercontent.com");
        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6ImY1ZjRiZjQ2ZTUyYjMxZDliNjI0OWY3MzA5YWQwMzM4NDAwNjgwY2QiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDEyOTE2MTk5MTgzLW1va2JjOXFybXNzdjhlMW9kZW1odjcyM2puYXVnY2ZrLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNzE0OTU2NDQ2NTYwNzkyNzU2OCIsImVtYWlsIjoibmV0aWQuY2FvamVuQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE2OTk1MDMyMDEsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lnUWlYQmg3ZG9TUV9DN25QZlJvUWdPc2h2WHpJaURFV2xESW1nWF9UTEt3PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwibG9jYWxlIjoiemgtQ04iLCJpYXQiOjE2OTk1MDM1MDEsImV4cCI6MTY5OTUwNzEwMSwianRpIjoiNTQxZTUxYTZkZDJjZGZkYmZkMjc5YWRkNDk0YWY2NzNiOGYxNTYwOCJ9.PMTxMgGlUQfWKS5GOUCGOzvFoc9qiwkhFI3QHSUcJsdyJIjnF7hhx9i9hg9S2_lBjahMeuak9MayiuOcspBDRHzpY1qKu6-DPy4VnkFdhVfJhcOBfgF6K-hC0RnJA9SX6q-A-K4gU-4S3Mvg0mTqhcoMHJKCX8SwU2ITyxtKanqlSHeM0xPPm6BMRP0gFdfnfhTTOln-Lxzap2ipuekYv657tkIvF66IPLB5lRDugPoSzEq1etAEb2rAHdGJ6xtxGByUu1PZuw0fHLsMzr-fXNen6HHUFW4rM6X5A_GtG8EhGitotUipE0jPRhkULbPTMBjjMcBx5rPq1OQ0f2jvgQ").await;
        data.unwrap();

        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6ImY1ZjRiZjQ2ZTUyYjMxZDliNjI0OWY3MzA5YWQwMzM4NDAwNjgwY2QiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDEyOTE2MTk5MTgzLW1va2JjOXFybXNzdjhlMW9kZW1odjcyM2puYXVnY2ZrLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNzE0OTU2NDQ2NTYwNzkyNzU2OCIsImVtYWlsIjoibmV0aWQuY2FvamVuQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE2OTk1MDMyMDEsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lnUWlYQmg3ZG9TUV9DN25QZlJvUWdPc2h2WHpJaURFV2xESW1nWF9UTEt3PXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwibG9jYWxlIjoiemgtQ04iLCJpYXQiOjE2OTk1MDM1MDEsImV4cCI6MTY5OTUwNzEwMSwianRpIjoiNTQxZTUxYTZkZDJjZGZkYmZkMjc5YWRkNDk0YWY2NzNiOGYxNTYwOCJ9.PMTxMgGlUQfWKS5GOUCGOzvFoc9qiwkhFI3QHSUcJsdyJIjnF7hhx9i9hg9S2_lBjahMeuak9MayiuOcspBDRHzpY1qKu6-DPy4VnkFdhVfJhcOBfgF6K-hC0RnJA9SX6q-A-K4gU-4S3Mvg0mTqhcoMHJKCX8SwU2ITyxtKanqlSHeM0xPPm6BMRP0gFdfnfhTTOln-Lxzap2ipuekYv657tkIvF66IPLB5lRDugPoSzEq1etAEb2rAHdGJ6xtxGByUu1PZuw0fHLsMzr-fXNen6HHUFW4rM6X5A_GtG8EhGitotUipE0jPRhkULbPTMBjjMcBx5rPq1OQ0f2jvgQ").await;
        data.unwrap();
    }

    #[tokio::test]
    async fn verify_access_token() {
        let client = AsyncClient::new("525360879715-3kfn0tge3t1nouvk9ol5jgaiv2rtp0s9.apps.googleusercontent.com");
        let token = "ya29.a0AfB_byAQCutpKSHb3-l7AZdv_HUPWVYgTbbCYbKT1xVgMgNX9kO2XvSiKp5C8NPmc846VGgpS0dCBYXTRnkCIcYt3QfdcWJmTviArX_C6bcLoznSyy3vCEqMOChUTOll6NCMMtvL2wR_C121PwGCk2_1Htdsp_J6xdhZaCgYKAdYSARISFQHGX2MiJKgr8WgVVyV7s2GbwhYctA0171";

        let payload = client.validate_access_token(token).await;
        payload.unwrap();
    }
}
