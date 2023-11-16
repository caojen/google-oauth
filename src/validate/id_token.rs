#[cfg(feature = "wasm")]
use web_time::{SystemTime, UNIX_EPOCH};
#[cfg(not(feature = "wasm"))]
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::BigUint;
use rsa::pkcs1v15::{VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Verifier};
use rsa::pkcs1v15::Signature;

use crate::{GOOGLE_ISS, GoogleIssuerNotMatchError, GooglePayload, HashAlgorithmUnimplementedError, IDTokenClientIDNotFoundError, MyResult};
use crate::Cert;
use crate::jwt_parser::JwtParser;

pub fn validate_info<T, V>(client_ids: T, parser: &JwtParser<GooglePayload>) -> MyResult<()>
    where
        T: AsRef<[V]>,
        V: AsRef<str>,
{
    if !client_ids.as_ref().iter().any(|c| c.as_ref() == parser.payload.aud.as_str()) {
        // bail!("id_token: audience provided does not match aud claim in the jwt");
        Err(IDTokenClientIDNotFoundError::new(&parser.payload.aud, client_ids))?
    }

    if !GOOGLE_ISS.contains(&(parser.payload.iss.as_str())) {
        Err(GoogleIssuerNotMatchError::new(&parser.payload.iss))?
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    if now > parser.payload.exp {
        #[cfg(not(test))]
        Err(crate::IDTokenExpiredError::new(now, parser.payload.exp))?
    }

    Ok(())
}

pub fn do_validate(cert: &Cert, parser: &JwtParser<GooglePayload>) -> MyResult<()> {
    match parser.header.alg.as_str() {
        "RS256" => validate_rs256(
            cert,
            parser.msg().as_str(),
            parser.sig.as_slice(),
        )?,
        a => Err(HashAlgorithmUnimplementedError::new(a))?,
    };

    Ok(())
}

fn decode<T: AsRef<[u8]>>(b64url: T) -> MyResult<Vec<u8>> {
    let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64url)?;

    Ok(bytes)
}

pub fn validate_rs256(cert: &Cert, msg: &str, sig: &[u8]) -> MyResult<()> {
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
