use serde::{Serialize, Deserialize};

/// `GooglePayload` is the user data from google.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GooglePayload {
    pub iss: String,
    pub nbf: u64,
    pub aud: String,
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub azp: String,
    pub name: String,
    pub picture: String,
    pub given_name: String,
    pub family_name: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
}
