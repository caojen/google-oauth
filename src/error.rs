use std::fmt::{Debug, Display, Formatter};
use std::time;
use crate::GOOGLE_ISS;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Any JSON error from [serde_json]
    JsonError(serde_json::Error),
    /// Any base64 decode error, from [base64]
    Base64DecodeError(base64::DecodeError),
    /// Error when id_token splits into 3 parts
    IDTokenSplitError(IDTokenSplitError),
    /// Error when id_token is expired
    IDTokenExpiredError(IDTokenExpiredError),
    /// Any [SystemTimeError] from [time]
    SystemTimeError(time::SystemTimeError),
    /// Error when id_token has an issuer which not listed in [GOOGLE_ISS]
    GoogleIssuerNotMatchError(GoogleIssuerNotMatchError),
    /// Error when id_token has a client_id which not listed when client was created.
    IDTokenClientIDNotFoundError(IDTokenClientIDNotFoundError),
    /// Any [rsa::signature::Error]
    RS256SignatureError(rsa::signature::Error),
    /// Any [rsa::errors::Error]
    RS256Error(rsa::errors::Error),
    /// Error when id_token has an unimplemented hash algorithm
    HashAlgorithmUnimplementedError(HashAlgorithmUnimplementedError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonError(e) => Display::fmt(&e, f),
            Self::Base64DecodeError(e) => Display::fmt(&e, f),
            Self::IDTokenSplitError(e) => Display::fmt(&e, f),
            Self::IDTokenExpiredError(e) => Display::fmt(&e, f),
            Self::SystemTimeError(e) => Display::fmt(&e, f),
            Self::GoogleIssuerNotMatchError(e) => Display::fmt(&e, f),
            Self::IDTokenClientIDNotFoundError(e) => Display::fmt(&e, f),
            Self::RS256SignatureError(e) => Display::fmt(&e, f),
            Self::RS256Error(e) => Display::fmt(&e, f),
            Self::HashAlgorithmUnimplementedError(e) => Display::fmt(&e, f),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    #[inline]
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err)
    }
}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64DecodeError(err)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IDTokenSplitError {
    pub expected: usize,
    pub get: usize,
}

impl Display for IDTokenSplitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "id_token split error, expected {} segments, but get {}", self.expected, self.get)
    }
}

impl std::error::Error for IDTokenSplitError {}

impl From<IDTokenSplitError> for Error {
    #[inline]
    fn from(err: IDTokenSplitError) -> Self {
        Self::IDTokenSplitError(err)
    }
}

impl IDTokenSplitError {
    #[inline]
    pub fn new(expected: usize, get: usize) -> Self {
        Self { expected, get }
    }
}

#[derive(Debug)]
pub struct IDTokenExpiredError {
    pub now: u64,
    pub exp: u64,
}

impl IDTokenExpiredError {
    #[inline]
    pub fn new(now: u64, exp: u64) -> Self {
        Self { now, exp }
    }
}

impl From<IDTokenExpiredError> for Error {
    #[inline]
    fn from(err: IDTokenExpiredError) -> Self {
        Self::IDTokenExpiredError(err)
    }
}

impl Display for IDTokenExpiredError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "token expired, {} > {}", self.now, self.exp)
    }
}

impl std::error::Error for IDTokenExpiredError {}

impl From<time::SystemTimeError> for Error {
    #[inline]
    fn from(err: time::SystemTimeError) -> Self {
        Self::SystemTimeError(err)
    }
}

#[derive(Debug)]
pub struct GoogleIssuerNotMatchError {
    pub get: String,
    pub expected: [&'static str; 2],
}

impl GoogleIssuerNotMatchError {
    #[inline]
    pub fn new<S: ToString>(get: S) -> Self {
        Self {
            get: get.to_string(),
            expected: GOOGLE_ISS,
        }
    }
}

impl Display for GoogleIssuerNotMatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "id_token issue error, iss = {}, but expects one of {:?}", self.get, self.expected)
    }
}

impl std::error::Error for GoogleIssuerNotMatchError {}

impl From<GoogleIssuerNotMatchError> for Error {
    #[inline]
    fn from(err: GoogleIssuerNotMatchError) -> Self {
        Self::GoogleIssuerNotMatchError(err)
    }
}

#[derive(Debug)]
pub struct IDTokenClientIDNotFoundError {
    pub get: String,
    pub expected: Vec<String>,
}

impl Display for IDTokenClientIDNotFoundError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "id_token client_id not found, get {}, but expected one of {:?}", &self.get, &self.expected)
    }
}

impl std::error::Error for IDTokenClientIDNotFoundError {}

impl From<IDTokenClientIDNotFoundError> for Error {
    fn from(err: IDTokenClientIDNotFoundError) -> Self {
        Self::IDTokenClientIDNotFoundError(err)
    }
}

impl IDTokenClientIDNotFoundError {
    pub fn new<S, T, V>(get: S, expected: T) -> Self
        where
            S: ToString,
            T: AsRef<[V]>,
            V: AsRef<str>
    {
        Self {
            get: get.to_string(),
            expected: expected.as_ref().iter().map(|e| e.as_ref().to_string()).collect(),
        }
    }
}

impl From<rsa::signature::Error> for Error {
    #[inline]
    fn from(err: rsa::signature::Error) -> Self {
        Self::RS256SignatureError(err)
    }
}

impl From<rsa::errors::Error> for Error {
    #[inline]
    fn from(err: rsa::errors::Error) -> Self {
        Self::RS256Error(err)
    }
}

#[derive(Debug)]
pub struct HashAlgorithmUnimplementedError {
    pub get: String,
}

impl HashAlgorithmUnimplementedError {
    #[inline]
    pub fn new<S: ToString>(get: S) -> Self {
        Self { get: get.to_string() }
    }
}

impl Display for HashAlgorithmUnimplementedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "id_token: unimplemented hash alg: {}", self.get)
    }
}

impl std::error::Error for HashAlgorithmUnimplementedError {}

impl From<HashAlgorithmUnimplementedError> for Error {
    #[inline]
    fn from(err: HashAlgorithmUnimplementedError) -> Self {
        Self::HashAlgorithmUnimplementedError(err)
    }
}
