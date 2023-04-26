use anyhow::bail;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD};

#[derive(Debug)]
pub struct JwtParser<'a, T> {
    pub parts: Vec<&'a str>,
    pub header: JwtHeader,
    pub payload: T,
    pub sig: Vec<u8>,
}

impl<'a, T> JwtParser<'a, T> where T: DeserializeOwned {
    pub fn parse(token: &'a str) -> anyhow::Result<JwtParser<'a, T>> {
        let parts: Vec<&'a str> = token.split('.').collect();
        dbg!(parts[0], parts[1], parts[2]);

        if parts.len() != 3 {
            bail!("invalid jwt token, token must have 3 segments, but get {}", parts.len());
        }

        Ok(Self {
            parts: parts.clone(),

            header: Self::parse_header(parts[0])?,
            payload: Self::parse_payload(parts[1])?,
            sig: Self::parse_signature(parts[2])?,
        })
    }

    fn parse_header(header: &str) -> anyhow::Result<JwtHeader> {
        let header = BASE64_URL_SAFE_NO_PAD.decode(header)?;
        let jh: JwtHeader = serde_json::from_slice(header.as_slice())?;

        Ok(jh)
    }

    fn parse_payload(payload: &str) -> anyhow::Result<T> {
        let payload = BASE64_URL_SAFE_NO_PAD.decode(payload)?;
        let payload: T = serde_json::from_slice(payload.as_slice())?;

        Ok(payload)
    }

    fn parse_signature(sig: &str) -> anyhow::Result<Vec<u8>> {
        let sig = BASE64_URL_SAFE_NO_PAD.decode(sig)?;

        Ok(sig)
    }

    pub fn hashed_content(&self) -> anyhow::Result<Vec<u8>> {
        let signed_content = self.parts[0].to_string() + "." + self.parts[1];
        let hexed = sha256::digest(signed_content.as_str());

        Ok(hex::decode(hexed)?)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}
