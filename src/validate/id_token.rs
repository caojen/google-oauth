#[cfg(feature = "wasm")]
use web_time::{SystemTime, UNIX_EPOCH};
#[cfg(not(feature = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::bail;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::BigUint;
use rsa::pkcs1v15::{VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Verifier};
use rsa::pkcs1v15::Signature;

use crate::{GOOGLE_ISS, GooglePayload};
use crate::Cert;
use crate::jwt_parser::JwtParser;

pub fn validate_info<T, V>(client_ids: T, parser: &JwtParser<GooglePayload>) -> anyhow::Result<()>
    where
        T: AsRef<[V]>,
        V: AsRef<str>,
{
    if !client_ids.as_ref().iter().any(|c| c.as_ref() == parser.payload.aud.as_str()) {
        bail!("id_token: audience provided does not match aud claim in the jwt");
    }

    if !GOOGLE_ISS.contains(&(parser.payload.iss.as_str())) {
        bail!("id_token: iss = {}, but expects one of {:?}", &parser.payload.iss, GOOGLE_ISS)
    }

    if SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() > parser.payload.exp {
        #[cfg(not(test))]
        bail!("id_token: token expired");
    }

    Ok(())
}

pub fn do_validate(cert: &Cert, parser: &JwtParser<GooglePayload>) -> anyhow::Result<()> {
    match parser.header.alg.as_str() {
        "RS256" => validate_rs256(
            cert,
            parser.msg().as_str(),
            parser.sig.as_slice(),
        )?,
        "ES256" => bail!("id_token: unimplemented alg: ES256"),
        a => bail!("id_token: expected JWT signed with RS256 or ES256, but found {}", a),
    };

    Ok(())
}

fn decode<T: AsRef<[u8]>>(b64url: T) -> anyhow::Result<Vec<u8>> {
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64url)?;

    Ok(bytes)
}

pub fn validate_rs256(cert: &Cert, msg: &str, sig: &[u8]) -> anyhow::Result<()> {
    let dn = decode(cert.n.as_bytes())?;
    let de = decode(cert.e.as_bytes())?;

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
