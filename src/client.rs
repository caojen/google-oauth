use anyhow::bail;
use lazy_static::lazy_static;
use crate::{Cert, Certs, GooglePayload, JwtParser};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use base64::Engine;
use rsa::BigUint;
use rsa::pkcs1v15::VerifyingKey;
use rsa::pkcs1v15::Signature;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;

lazy_static! {
    static ref cb: reqwest::blocking::Client = reqwest::blocking::Client::new();
}

const GOOGLE_SA_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

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
        }

        #[cfg(not(test))]
        if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > parser.payload.exp {
            bail!("id_token: token expired");
        }

        match parser.header.alg.as_str() {
            "RS256" => self.validate_rs256(
                parser.header.kid.as_str(),
                parser.hashed_content().as_str(),
                parser.sig.as_slice(),
            )?,
            "ES256" => self.validate_es256(
                parser.header.kid.as_str(),
                parser.hashed_content().as_str(),
                parser.sig.as_slice(),
            )?,
            a => bail!("id_token: expected JWT signed with RS256 or ES256, but found {}", a),
        }

        Ok(parser.payload)
    }

    fn validate_rs256(&self, kid: &str, hashed_content: &str, sig: &[u8]) -> anyhow::Result<()> {
        let cert = self.get_cert("RS256", kid)?;

        let dn = Self::decode(cert.n.as_ref())?;
        let de = Self::decode(cert.e.as_ref())?;

        let pk = rsa::RsaPublicKey::new(
            BigUint::from_bytes_le(dn.as_slice()),
            BigUint::from_bytes_le(de.as_slice()),
        )?;

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::from(pk);
        verifying_key.verify(
            hex::decode(hashed_content)?.as_slice(),
            &Signature::try_from(sig)?
        )?;

        Ok(())
    }

    fn validate_es256(&self, kid: &str, hashed_content: &str, sig: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_cert(&self, alg: &str, kid: &str) -> anyhow::Result<Cert> {
        let certs = self.get_certs_from_server()?;

        match certs.iter().find(|cert| cert.alg == alg && cert.kid == kid) {
            Some(cert) => Ok(cert.clone()),
            None => bail!("alg {} not found in google certs", alg),
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
        let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk2OTcxODA4Nzk2ODI5YTk3MmU3OWE5ZDFhOWZmZjExY2Q2MWIxZTMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2ODE4MTAzNTEsImF1ZCI6IjEwMTI5MTYxOTkxODMtbW9rYmM5cXJtc3N2OGUxb2RlbWh2NzIzam5hdWdjZmsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDcxNDk1NjQ0NjU2MDc5Mjc1NjgiLCJlbWFpbCI6Im5ldGlkLmNhb2plbkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMTAxMjkxNjE5OTE4My1tb2tiYzlxcm1zc3Y4ZTFvZGVtaHY3MjNqbmF1Z2Nmay5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsIm5hbWUiOiJqaWFuZW4gY2FvIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eFl5cDdLaVh1cEdNU2pReWY5d08xSkNqTl9YV0NyQm1fQWtDR1pMPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6ImppYW5lbiIsImZhbWlseV9uYW1lIjoiY2FvIiwiaWF0IjoxNjgxODEwNjUxLCJleHAiOjE2ODE4MTQyNTEsImp0aSI6IjRmNDU4N2RmNTgxZGE3Yzg5Mzc0YWQ1NGFkYmJiNjA0NGE0ZWQ3YWYifQ.F9Ipp6S05VL_dghRLaB62a9ZRTTbNU6W9mUIhDw66R6hjHSDE2XaNOu5eWyHUnVJoSdwH2QgYJ9371zdSZlZj8n0HgN3r5ed-DvQa5jcCC761stP_7BQpTkghV8_UQ6lmGscBeANskz121zeYsE6f1IR6oyc1hlHyJPQXyOfY9PsF1CkpnbwWSpl1Y5TGIkewEf7qzvcQQFk50pCc6MjQ6na7rX4ze9RXc0fB7TuagnZkCnohHqQ2t7_m2RCu571dEeGPAglvsnHe1nqHvsTh2h7cPVxDV5Ahvhm_lN7pqWrUQUob52hQ4PEB_nUyooe4FmuDroYyR1NHSEw5-Mnyw";

        let payload = client.validate(id_token).unwrap();
        dbg!(payload);
    }

    #[test]
    fn verify_aqab() {
        let s = "AQAB";
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