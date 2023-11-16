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
    client_ids: Vec<String>,
    timeout: Duration,
    cached_certs: Arc<RwLock<Certs>>,
}

impl Client {
    /// Create a new blocking client.
    pub fn new<S: ToString>(client_id: S) -> Self {
        let client_id = client_id.to_string();

        Self::new_with_vec(&[client_id])
    }

    /// Create a new blocking client, with multiple client ids.
    pub fn new_with_vec<T, V>(client_ids: T) -> Self
        where
            T: AsRef<[V]>,
            V: AsRef<str>
    {
        Self {
            client_ids: client_ids
                .as_ref()
                .iter()
                .map(|c| c.as_ref().to_string())
                .collect(),
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
    pub fn validate_id_token<S>(&self, token: S) -> MyResult<GooglePayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(token)?;

        id_token::validate_info(&self.client_ids, &parser)?;

        let cert = self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str())?;

        id_token::do_validate(&cert, &parser)?;

        Ok(parser.payload)
    }

    fn get_cert(&self, alg: &str, kid: &str) -> MyResult<Cert> {
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
    pub fn validate_access_token<S>(&self, token: S) -> MyResult<GoogleAccessTokenPayload>
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
