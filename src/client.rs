#![allow(non_upper_case_globals)]

use lazy_static::lazy_static;
use crate::{Cert, Certs, DEFAULT_TIMEOUT, find_cert, GOOGLE_SA_CERTS_URL, GoogleAccessTokenPayload, GooglePayload, JwtParser};
use std::time::{Duration};
use crate::validate::{id_token, access_token};

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

    /// Try to validate access token. If succeed, return the user info.
    pub fn validate_access_token<S>(&self, token: S) -> anyhow::Result<GoogleAccessTokenPayload>
        where S: AsRef<str>
    {
        let token = token.as_ref();

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_id_token() {
        let client = Client::new("525360879715-3kfn0tge3t1nouvk9ol5jgaiv2rtp0s9.apps.googleusercontent.com");
        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6IjdkMzM0NDk3NTA2YWNiNzRjZGVlZGFhNjYxODRkMTU1NDdmODM2OTMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1MjUzNjA4Nzk3MTUtM2tmbjB0Z2UzdDFub3V2azlvbDVqZ2FpdjJydHAwczkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1MjUzNjA4Nzk3MTUtM2tmbjB0Z2UzdDFub3V2azlvbDVqZ2FpdjJydHAwczkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDcxNDk1NjQ0NjU2MDc5Mjc1NjgiLCJlbWFpbCI6Im5ldGlkLmNhb2plbkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmJmIjoxNjk3Nzc2NjIwLCJuYW1lIjoiamlhbmVuIGNhbyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NJZ1FpWEJoN2RvU1FfQzduUGZSb1FnT3Nodlh6SWlERVdsREltZ1hfVExLdz1zOTYtYyIsImdpdmVuX25hbWUiOiJqaWFuZW4iLCJmYW1pbHlfbmFtZSI6ImNhbyIsImxvY2FsZSI6InpoLUNOIiwiaWF0IjoxNjk3Nzc2OTIwLCJleHAiOjE2OTc3ODA1MjAsImp0aSI6IjBlMGIxY2Q1M2Q1ZDY2NTk2NzQxOTQ5YjlkMjQyNThkNDhjOTVmNDAifQ.fbnfPzuwbWjJGMivDmHcZuPqRjFxajQL28CU40IGzArxSXZF3nzhyWRxzsA-t9yf4BmrsRPuUEAENqfKZwEc9z7csNuU1nw8TgrQcGl2BVS2kZrpLDwGe5b-3Vhjne8qDu4ZJC6QalKl1YqL4UcvWYHLEhj1n3SKAWzrd7MXfsanm3RsoNN7ErVdzBcq3FAr29MyYJfW8-MSEL4VHFRl8rkJAI-pa4fgwZVVpUxk_yqG5em5G2uAE5mmRGc8L3XgS0i-YudRIh7i95j8EhZsqTYEa1yHqWAlYlXhnVWetukpHl1QfwMVFbCtoAKGTc2wxq7RnMYTTrJeNWaC9hJEhw");
        data.unwrap();
    }
}
