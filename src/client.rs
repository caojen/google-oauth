#![allow(non_upper_case_globals)]
#![cfg(feature = "blocking")]

use anyhow::bail;
use lazy_static::lazy_static;
use crate::{Cert, Certs, GooglePayload, JwtParser};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::validate::validate_rs256;

lazy_static! {
    static ref cb: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

const GOOGLE_SA_CERTS_URL: &str = crate::GOOGLE_SA_CERTS_URL;
const GOOGLE_ISS: &str = crate::GOOGLE_ISS;
const DEFAULT_TIMEOUT: u64 = crate::DEFAULT_TIMEOUT;

#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
    timeout: Duration,
}

impl Client {
    pub fn new<S: Into<String>>(client_id: S) -> Self {
        Self {
            client_id: client_id.into(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        }
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;

        self
    }

    pub fn validate_id_token<S: AsRef<str>>(&self, id_token: S) -> anyhow::Result<GooglePayload> {
        let id_token = id_token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(id_token)?;

        if !self.client_id.is_empty() && self.client_id != parser.payload.aud {
            bail!("id_token: audience provided does not match aud claim in the jwt");
        } else if parser.payload.iss != GOOGLE_ISS {
            bail!("id_token: iss = {}, but expects {}", &parser.payload.iss, GOOGLE_ISS);
        }

        if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > parser.payload.exp {
            bail!("id_token: token expired");
        }

        let cert = self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str())?;

        match parser.header.alg.as_str() {
            "RS256" => validate_rs256(
                    &cert,
                    parser.msg().as_str(),
                    parser.sig.as_slice(),
                )?,
            "ES256" => bail!("id_token: unimplemented alg: ES256"),
            a => bail!("id_token: expected JWT signed with RS256 or ES256, but found {}", a),
        }

        Ok(parser.payload)
    }

    fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        let certs = self.get_certs_from_server()?;

        match certs.iter().find(|cert| cert.alg == alg && cert.kid == kid) {
            Some(cert) => Ok(cert.clone()),
            None => bail!("alg {}, kid = {} not found in google certs", alg, kid),
        }
    }

    fn get_certs_from_server(&self) -> anyhow::Result<Vec<Cert>> {
        let certs = cb.get(GOOGLE_SA_CERTS_URL)
            .timeout(self.timeout)
            .send()?
            .text()?;
        let certs: Certs = serde_json::from_str(&certs)?;

        Ok(certs.keys)
    }
}
