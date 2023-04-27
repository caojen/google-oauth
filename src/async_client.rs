use std::time::Duration;
use anyhow::bail;
use lazy_static::lazy_static;
use crate::{Cert, Certs, DEFAULT_TIMEOUT, find_cert, GOOGLE_SA_CERTS_URL, GooglePayload, JwtParser};
use crate::validate::{do_validate, validate_id_token_info, validate_rs256};

lazy_static! {
    static ref ca: reqwest::Client = reqwest::Client::new();
}

#[derive(Debug, Clone)]
pub struct AsyncClient {
    client_id: String,
    timeout: Duration,
}

impl AsyncClient {
    pub fn new<S: ToString>(client_id: S) -> Self {
        Self {
            client_id: client_id.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        }
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        if d.as_nanos() != 0 {
            self.timeout = d;
        }

        self
    }

    pub async fn validate_id_token<S>(&self, id_token: S) -> anyhow::Result<GooglePayload>
        where S: AsRef<str>
    {
        let id_token = id_token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(id_token)?;

        validate_id_token_info(&self.client_id, &parser)?;

        let cert = self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str()).await?;

        do_validate(&cert, &parser)?;

        Ok(parser.payload)
    }

    async fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        let certs = self.get_certs_from_server().await?;

        find_cert(certs, alg, kid)
    }

    async fn get_certs_from_server(&self) -> anyhow::Result<Vec<Cert>> {
        let certs = ca.get(GOOGLE_SA_CERTS_URL)
            .timeout(self.timeout)
            .send()
            .await?
            .text()
            .await?;

        let certs: Certs = serde_json::from_str(&certs)?;

        Ok(certs.keys)
    }
}