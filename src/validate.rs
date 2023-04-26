use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::BigUint;
use rsa::pkcs1v15::{VerifyingKey};
use rsa::sha2::{Sha256};
use rsa::signature::{Verifier};
use rsa::pkcs1v15::Signature;

use crate::Cert;

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
