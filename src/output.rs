use serde::{Serialize, Deserialize};

/// `GooglePayload` is the user data from google.
/// see https://developers.google.com/identity/openid-connect/openid-connect for more info.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
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

    // These fields doesn't list in document, but it exists
    pub nbf: Option<u64>,
    pub jti: Option<String>,
}
