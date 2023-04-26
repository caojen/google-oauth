#![allow(non_upper_case_globals)]

use anyhow::bail;
use lazy_static::lazy_static;
use crate::{Cert, Certs, GooglePayload, JwtParser};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::Engine;
use rsa::{BigUint};
use rsa::pkcs1v15::{VerifyingKey};
use rsa::pkcs1v15::Signature;
use rsa::sha2::{Sha256};
use rsa::signature::{Verifier};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;

lazy_static! {
    static ref cb: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

const GOOGLE_SA_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISS: &str = "https://accounts.google.com";

#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
    timeout: Duration,
}

impl Client {
    pub fn new<S: Into<String>>(client_id: S) -> Self {
        Self {
            client_id: client_id.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;

        self
    }

    pub fn validate<S: AsRef<str>>(&self, id_token: S) -> anyhow::Result<GooglePayload> {
        let id_token = id_token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(id_token)?;

        if !self.client_id.is_empty() && self.client_id != parser.payload.aud {
            bail!("id_token: audience provided does not match aud claim in the jwt");
        } else if parser.payload.iss != GOOGLE_ISS {
            bail!("id_token: iss = {}, but expects {}", &parser.payload.iss, GOOGLE_ISS);
        }

        if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > parser.payload.exp {
            #[cfg(not(test))]
            bail!("id_token: token expired");
        }

        match parser.header.alg.as_str() {
            "RS256" => self.validate_rs256(
                parser.header.kid.as_str(),
                parser.msg().as_str(),
                parser.sig.as_slice(),
            )?,
            "ES256" => bail!("id_token: unimplemented alg: ES256"),
            a => bail!("id_token: expected JWT signed with RS256 or ES256, but found {}", a),
        }

        Ok(parser.payload)
    }

    fn validate_rs256(&self, kid: &str, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
        let cert = self.get_cert("RS256", kid)?;

        let dn = Self::decode(cert.n.as_ref())?;
        let de = Self::decode(cert.e.as_ref())?;

        let pk = rsa::RsaPublicKey::new(
            BigUint::from_bytes_be(dn.as_slice()),
            BigUint::from_bytes_be(de.as_slice()),
        )?;

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new_with_prefix(pk);

        verifying_key.verify(
            msg.as_bytes(),
            &Signature::try_from(sig)?,
        )?;

        Ok(())
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

    fn decode(b64: &str) -> anyhow::Result<Vec<u8>> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64)?;

        Ok(bytes)
    }
}
