use std::fmt::{Debug, Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Any JSON error from [serde_json]
    JsonError(serde_json::Error),
    /// Any base64 decode error, from [base64]
    Base64DecodeError(base64::DecodeError),
    /// Error when id_token split into 3 parts
    IDTokenSplitError(IDTokenSplitError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonError(e) => Display::fmt(&e, f),
            Self::Base64DecodeError(e) => Display::fmt(&e, f),
            Self::IDTokenSplitError(e) => Display::fmt(&e, f),
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
        Self {
            expected,
            get,
        }
    }
}
