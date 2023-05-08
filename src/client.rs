#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use crate::{Cert, Certs, DEFAULT_TIMEOUT, find_cert, GOOGLE_SA_CERTS_URL, GooglePayload, JwtParser};
use std::time::{Duration};
use crate::validate::{do_validate, validate_id_token_info};

lazy_static! {
    static ref cb: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

/// Client is a blocking client to do verification.
#[derive(Debug, Clone)]
pub struct Client {
    client_id: String,
    timeout: Duration,
}

impl Client {
    /// Create a new client.
    pub fn new<S: ToString>(client_id: S) -> Self {
        Self {
            client_id: client_id.to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT),
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
    pub fn validate_id_token<S: AsRef<str>>(&self, id_token: S) -> anyhow::Result<GooglePayload> {
        let id_token = id_token.as_ref();

        let parser: JwtParser<GooglePayload> = JwtParser::parse(id_token)?;

        validate_id_token_info(&self.client_id, &parser)?;

        let cert = self.get_cert(parser.header.alg.as_str(), parser.header.kid.as_str())?;

        do_validate(&cert, &parser)?;

        Ok(parser.payload)
    }

    fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        let certs = self.get_certs_from_server()?;

        find_cert(certs, alg, kid)
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
        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc3NzBiMDg1YmY2NDliNzI2YjM1NzQ3NjQwMzBlMWJkZTlhMTBhZTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2ODM1Mjg4NTEsImF1ZCI6IjEwMTI5MTYxOTkxODMtbW9rYmM5cXJtc3N2OGUxb2RlbWh2NzIzam5hdWdjZmsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDcxNDk1NjQ0NjU2MDc5Mjc1NjgiLCJlbWFpbCI6Im5ldGlkLmNhb2plbkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eFl5cDdLaVh1cEdNU2pReWY5d08xSkNqTl9YV0NyQm1fQWtDR1pMPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwiaWF0IjoxNjgzNTI5MTUxLCJleHAiOjE2ODM1MzI3NTEsImp0aSI6IjE2ZmIwMzhkYzVmYjAzM2MwZmI5YjRiMTVlNGYyYzU2YjExMzU5OTEifQ.Xu9UOYMbmyNp8st99FP72lpTlAX0trsZC0jQPYgnNFPwlZCK7QTA3Efnww31vc91KM87CjNw4FkhBpcHrk8PcXTs1mx2CfDLOzTM_5dtBHxbHhRV4laXWxsMDE60rDRFLy1w8SrB43YJHjX8aWnrBRKZjfa4ycUzGrTQhiIC-GpW6sSar2VJuUMfwddzPg8VZGi4rKQF_3aGwv3djXlJzvQKJAmpEg2Pfuz6Nn-4TeWBIu861CINMdKkBq0RmEijWqvxaWThPcJKFBlpyb_9AxSf_0NSv_b-GQ1ZA9iAWivSzWzP6e5BsU5pwC8H2PSiUHMvotdSzw25eFOIRdr5kw");
        data.unwrap();
    }
}
