use serde::{Serialize, Deserialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// `GooglePayload` is the user data from google.
///
/// see https://developers.google.com/identity/openid-connect/openid-connect for more info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "wasm", wasm_bindgen(getter_with_clone))]
pub struct GooglePayload {
    // These fields are marked `always`.
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub sub: String,

    // These fields are optional.
    pub at_hash: Option<String>,
    pub azp: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub hd: Option<String>,
    pub locale: Option<String>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub picture: Option<String>,

    // These fields not list in document, but it may exist
    pub nbf: Option<u64>,
    pub jti: Option<String>,
}

/// `GoogleAccessTokenPayload` is the user data when using access token
///
/// reference: https://stackoverflow.com/questions/16501895/how-do-i-get-user-profile-using-google-access-token
///
/// reference: https://gist.github.com/evanj/e415d808dbb6c2a0bd866cd9d17ef5aa
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[cfg_attr(feature = "wasm", wasm_bindgen(getter_with_clone))]
pub struct GoogleAccessTokenPayload {
    pub sub: String,
    pub picture: Option<String>,
    pub name: Option<String>,
    pub locale: Option<String>,
    pub given_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}
