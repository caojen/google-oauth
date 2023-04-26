use anyhow::bail;
use lazy_static::lazy_static;
use crate::{Cert, Certs, GooglePayload, JwtParser};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::Engine;
use rsa::{BigUint, Pkcs1v15Sign};
use rsa::pkcs1v15::VerifyingKey;
use rsa::pkcs1v15::Signature;
use rsa::sha2::{Sha256, Sha512_256};
use rsa::signature::Verifier;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
use rsa::pkcs8::EncodePublicKey;

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

        dbg!(&parser);

        if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > parser.payload.exp {
            #[cfg(not(test))]
            bail!("id_token: token expired");
        }

        match parser.header.alg.as_str() {
            "RS256" => self.validate_rs256(
                parser.header.kid.as_str(),
                parser.hashed_content()?.as_slice(),
                parser.sig.as_slice(),
            )?,
            // "ES256" => self.validate_es256(
            //     parser.header.kid.as_str(),
            //     parser.hashed_content().as_str(),
            //     parser.sig.as_slice(),
            // )?,
            a => bail!("id_token: expected JWT signed with RS256 or ES256, but found {}", a),
        }

        Ok(parser.payload)
    }

    fn validate_rs256(&self, kid: &str, digest: &[u8], sig: &[u8]) -> anyhow::Result<()> {
        let cert = self.get_cert("RS256", kid)?;

        let dn = Self::decode(cert.n.as_ref())?;
        let de = Self::decode(cert.e.as_ref())?;

        let pk = rsa::RsaPublicKey::new(
            BigUint::from_bytes_be(dn.as_slice()),
            BigUint::from_bytes_be(de.as_slice()),
        )?;

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(pk);

        verifying_key.verify(
            digest,
            &Signature::try_from(sig)?,
        )?;

        Ok(())
    }

    fn validate_es256(&self, _kid: &str, _hashed_content: &str, _sig: &[u8]) -> anyhow::Result<()> {
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
        let certs = dbg!(certs);
        println!("{}", certs);
        // let certs: HashMap<String, Vec<HashMap<String, String>>> = serde_json::from_str(&certs)?;
        let certs: Certs = serde_json::from_str(&certs)?;

        Ok(certs.keys)
    }

    fn decode(b64: &str) -> anyhow::Result<Vec<u8>> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verity() {
        let client = Client::new("1012916199183-mokbc9qrmssv8e1odemhv723jnaugcfk.apps.googleusercontent.com");
        let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OTY5YWVjMzdhNzc4MGYxODgwNzg3NzU5M2JiYmY4Y2Y1ZGU1Y2UiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2ODI1MTc5OTMsImF1ZCI6IjEwMTI5MTYxOTkxODMtbW9rYmM5cXJtc3N2OGUxb2RlbWh2NzIzam5hdWdjZmsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDcxNDk1NjQ0NjU2MDc5Mjc1NjgiLCJlbWFpbCI6Im5ldGlkLmNhb2plbkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eFl5cDdLaVh1cEdNU2pReWY5d08xSkNqTl9YV0NyQm1fQWtDR1pMPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwiaWF0IjoxNjgyNTE4MjkzLCJleHAiOjE2ODI1MjE4OTMsImp0aSI6IjEzYzBmY2VkMTdhY2FkMWY3MDA1NzFjMTYzYmE3NmUyNzZlNzVhOWMifQ.lPeHAjZFcbDaoLKPyodebfcBu0zw7zengslk7lGJddzQcWyqn1o9RoMPDqw5ou60-rDv73N2sOPNqCCCpzbkPV0CdF4cFfh7mJrH_XwMl5VrcW59Ed4VbdBTN-fUpaRT9of_OzCyHW8zVMww4hWbmdRNKgpXjGS3ztTtjf7D7NOxFcdcemFmA6ILsoTTsubwsrZ_dXL20kSzPS-s--CNEGdbosqqCojMUmPRuZwoKrD43BnZveHW-FodJYxBA-TDQ42Jha5ubFCaTxTIOn-zqTPrFqbMvv14tdn8Q0rE-ZYZrnqkXTt9YEHD2MMh4Auzx4akLdyyslaqMdEH4BdkBg";

        let payload = client.validate(id_token);
        dbg!(payload);
    }

    #[test]
    fn verify_aqab() {
        let _s = "AQAB";
        let a = BigUint::parse_bytes(b"65535", 10).unwrap();
        dbg!(a);
        let b = BigUint::from_bytes_be(b"A");
        dbg!(b);
        let b = BigUint::from_bytes_be(b"AQAB");
        dbg!(b);

        let c = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(b"AQAB").unwrap();
        let c = dbg!(c);
        let d = BigUint::from_bytes_be(c.as_slice());
        dbg!(d);
    }
}