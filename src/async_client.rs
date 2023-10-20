#![allow(non_upper_case_globals)]

use std::time::Duration;
use lazy_static::lazy_static;
use crate::{Cert, Certs, DEFAULT_TIMEOUT, find_cert, GOOGLE_OAUTH_V3_USER_INFO_API, GOOGLE_SA_CERTS_URL, GoogleAccessTokenPayload, GooglePayload, JwtParser};
use crate::validate::id_token;

lazy_static! {
    static ref ca: reqwest::Client = reqwest::Client::new();
}

/// AsyncClient is an async client to do verification.
#[derive(Debug, Clone)]
pub struct AsyncClient {
    client_id: String,
    timeout: Duration,
}

impl AsyncClient {
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
        let client = AsyncClient::new("1012916199183-mokbc9qrmssv8e1odemhv723jnaugcfk.apps.googleusercontent.com");
        let data = client.validate_id_token("eyJhbGciOiJSUzI1NiIsImtpZCI6ImM3ZTExNDEwNTlhMTliMjE4MjA5YmM1YWY3YTgxYTcyMGUzOWI1MDAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMDEyOTE2MTk5MTgzLW1va2JjOXFybXNzdjhlMW9kZW1odjcyM2puYXVnY2ZrLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNzE0OTU2NDQ2NTYwNzkyNzU2OCIsImVtYWlsIjoibmV0aWQuY2FvamVuQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE2OTM0NTAwNDIsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBY0hUdGRPN005V0ZOUnF6VDZ2SF9VTXBsTGhTNUtxZWVjOHhwY3h0NmJuaTVKSUlBPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwibG9jYWxlIjoiemgtQ04iLCJpYXQiOjE2OTM0NTAzNDIsImV4cCI6MTY5MzQ1Mzk0MiwianRpIjoiOTRkZTZlZTFkMzk4ODY4Mzk2NmExZGE5MTE5MjVkNDQwYzA1MjM0OCJ9.U9m2xpMzQO8POBjJ1qkrkpNDzf7MqxfM0f8uENvzuNdD_30RpvLoa1rMcmTdQMn7Fp5thTW0oiW6tm1Wb4H3AxnIbadOKd2XNNOlrES7tL0snSGj8LMDWVE3VF6RC6Q0OgIgcnR6IFA-9Dj9YTyNhRjsDgtCVh1n8pyvcuNjMAE62x-Ehj9ByV-41mG34IHFymC8CFtIVYHBKvJOJbP7yej_e10lqMOp0ksF_7tCy762ic2cI4P9lYtbat6EtOwMATPxka9PNRSZr22yKS_6wHGEjU91urnMnzVA3JNk0aN7eigZt3qfZSpHdU7PNbaHNi6kOruRfFbxkpvJ6zMLOA").await;

        data.unwrap();
    }

    #[tokio::test]
    async fn verify_access_token() {
        let client = AsyncClient::new("525360879715-3kfn0tge3t1nouvk9ol5jgaiv2rtp0s9.apps.googleusercontent.com");
        let token = "ya29.a0AfB_byCH_ODaYF16gXLDn7yO6M6En58FEyBfWeentCVJ664dy6ASRYDfVcYoN4qDDjWwFl7_9R6deSPndy8ZZf1sO5X078pqY5oH4bDbydc-v3Ulux_LeIhWZQQybfjJKdFGjmLaWGxOfYaiKhJGOFFzxI41XuX8FX9waCgYKAfMSARISFQGOcNnCqo7b7NhcUZjGUK6B9su5vw0171";

        let payload = client.validate_access_token(token).await;
        payload.unwrap();
    }
}
