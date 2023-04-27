#![allow(non_upper_case_globals)]

use anyhow::bail;
use lazy_static::lazy_static;
use crate::{Cert, Certs, DEFAULT_TIMEOUT, GOOGLE_SA_CERTS_URL, GooglePayload, JwtParser};
use std::time::{Duration};
use crate::validate::{validate_id_token_info, validate_rs256};

lazy_static! {
    static ref cb: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

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

        validate_id_token_info(&self.client_id, &parser)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_id_token() {
        let client = Client::new("1012916199183-mokbc9qrmssv8e1odemhv723jnaugcfk.apps.googleusercontent.com");
        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OTY5YWVjMzdhNzc4MGYxODgwNzg3NzU5M2JiYmY4Y2Y1ZGU1Y2UiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2ODI1Mjc0MzQsImF1ZCI6IjEwMTI5MTYxOTkxODMtbW9rYmM5cXJtc3N2OGUxb2RlbWh2NzIzam5hdWdjZmsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDcxNDk1NjQ0NjU2MDc5Mjc1NjgiLCJlbWFpbCI6Im5ldGlkLmNhb2plbkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eFl5cDdLaVh1cEdNU2pReWY5d08xSkNqTl9YV0NyQm1fQWtDR1pMPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwiaWF0IjoxNjgyNTI3NzM0LCJleHAiOjE2ODI1MzEzMzQsImp0aSI6ImEzMWM1MDllOWQ2MWE3MWNiODYxYTYwMzE5OGY4ZWRhMGRjMTgxYjMifQ.vaMGWcLlSym2WVW-YmXAdKkZ4aPcFltlxFyeT6WfSLSXGosqhS9t-_YrCcg-HQjaw_qBEqwdYbD19jvAcFkQqmuYIiqyJJPR9gsyUpqQqvfwY1jq_UQYLkkkepdVf0_N18Pqsj94uj_xTUoPH3u3P2s2PJQwSgJ7j15wCCqBzhiXlUcQMvLdvnUNKbAxDWrTxMELupbApzQhNy5_aiYkDNVsFfV7iU78UQ4VlR5Zhi0aEmYG4827MfY-DVIIveR6NXrzw5yRhcufCxKU4hZBAti6ZhgBqyYlEOSeCGhu55dQzwpyOVpmjnYSmt-_2Ntd3WcEwQ9NuEf3dBblHDBSQQ");
        data.unwrap();
    }
}
