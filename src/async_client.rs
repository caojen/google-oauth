#![allow(non_upper_case_globals)]

use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};
use lazy_static::lazy_static;
use log::debug;
use async_lock::RwLock;
use crate::{DEFAULT_TIMEOUT, GOOGLE_OAUTH_V3_USER_INFO_API, GOOGLE_SA_CERTS_URL, GoogleAccessTokenPayload, GooglePayload, MyResult, utils};
use crate::certs::{Cert, Certs};
use crate::jwt_parser::JwtParser;
use crate::validate::id_token;

lazy_static! {
    static ref ca: reqwest::Client = reqwest::Client::new();
}

/// AsyncClient is an async client to do verification.
#[derive(Debug, Clone)]
pub struct AsyncClient {
    client_ids: Arc<RwLock<Vec<String>>>,
    timeout: Duration,
    cached_certs: Arc<RwLock<Certs>>,
}

impl AsyncClient {
    /// Create a new async client.
    pub fn new<S: ToString>(client_id: S) -> Self {
        let client_id = client_id.to_string();
        Self::new_with_vec([client_id])
    }

    /// Create a new async client, with multiple client ids.
    pub fn new_with_vec<T, V>(client_ids: T) -> Self
        where
            T: AsRef<[V]>,
            V: AsRef<str>,
    {
        Self {
            client_ids: Arc::new(RwLock::new(
                client_ids
                    .as_ref()
                    .iter()
                    .map(|c| c.as_ref())
                    .filter(|c| !c.is_empty())
                    .map(|c| c.to_string())
                    .collect()
            )),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT),
            cached_certs: Arc::default(),
        }
    }

    /// Add a new client_id for future validating.
    ///
    /// Note: this function is thread safe.
    pub async fn add_client_id<T: ToString>(&mut self, client_id: T) {
        let client_id = client_id.to_string();

        if !client_id.is_empty() {
            // check if client_id exists?
            if self.client_ids.read().await.contains(&client_id) {
                return
            }

            self.client_ids.write().await.push(client_id)
        }
    }

    /// Remove a client_id, if it exists.
    ///
    /// Note: this function is thread safe.
    pub async fn remove_client_id<T: AsRef<str>>(&mut self, client_id: T) {
        let to_delete = client_id.as_ref();

        if !to_delete.is_empty() {
            let mut client_ids = self.client_ids.write().await;
            client_ids.retain(|id| id != to_delete)
        }
    }

    /// Set the timeout (used in fetching google certs).
    /// Default timeout is 5 seconds. Zero timeout will be ignored.
    pub fn timeout(mut self, d: Duration) -> Self {
        if !d.is_zero() {
            self.timeout = d;
        }

        self
    }

    /// Do verification with `id_token`. If success, return the user data.
    pub async fn validate_id_token<S>(&self, token: S) -> MyResult<GooglePayload>
    where S: AsRef<str>
    {
        let token = token.as_ref();
        let client_ids = self.client_ids.read().await;

        let parser = JwtParser::parse(token)?;
        id_token::validate_info(&*client_ids, &parser)?;

        let cert = self.get_cert(&parser.header.alg, &parser.header.kid).await?;
        id_token::do_validate(&cert, &parser)?;

        Ok(parser.payload)
    }

    async fn get_cert(&self, alg: &str, kid: &str) -> MyResult<Cert> {
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
        let max_age = utils::parse_max_age_from_async_resp(&resp);

        let info = resp.bytes().await?;
        *cached_certs = serde_json::from_slice(&info)?;

        cached_certs.set_cache_until(Instant::now().add(Duration::from_secs(max_age)));
        cached_certs.find_cert(alg, kid)
    }

    /// Try to validate access token. If success, return the user info.
    pub async fn validate_access_token<S>(&self, token: S) -> MyResult<GoogleAccessTokenPayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        let info = ca.get(format!("{}?access_token={}", GOOGLE_OAUTH_V3_USER_INFO_API, token))
            .timeout(self.timeout)
            .send()
            .await?
            .bytes()
            .await?;

        Ok(serde_json::from_slice(&info)?)
    }
}

impl Default for AsyncClient {
    fn default() -> Self {
        Self::new_with_vec::<&[_; 0], &'static str>(&[])
    }
}
