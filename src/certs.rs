#[cfg(not(feature = "wasm"))]
use std::time::Instant;
#[cfg(feature = "wasm")]
use web_time::Instant;
use log::debug;
use serde::{Deserialize, Serialize};
use crate::{IDTokenCertNotFoundError, MyResult};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Certs {
    keys: Vec<Cert>,

    /// MUST refresh certs from Google server again, when one of following is matched:
    /// 1. cache_until is None,
    /// 2. if let Some(time) = cache_until, current time > time
    #[serde(skip)]
    cache_until: Option<Instant>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cert {
    pub kid: String,
    pub e: String,
    pub alg: String,
    pub kty: String,
    pub n: String,
}

impl Certs {
    pub fn find_cert<T: AsRef<str>>(&self, alg: T, kid: T) -> MyResult<Cert> {
        let alg = alg.as_ref();
        let kid = kid.as_ref();

        match self.keys.iter().find(|cert| cert.alg == alg && cert.kid == kid) {
            Some(cert ) => Ok(cert.clone()),
            None => Err(IDTokenCertNotFoundError::new(alg, kid))?,
        }
    }

    #[inline]
    pub fn set_cache_until<T>(&mut self, cache_until: T)
        where T: Into<Option<Instant>>
    {
        let cache_until = cache_until.into();

        debug!("set cache until to {:?}", cache_until);
        self.cache_until = cache_until;
    }

    #[inline]
    pub fn need_refresh(&self) -> bool {
        self
            .cache_until
            .map(|until| until <= Instant::now())
            .unwrap_or(true)
    }
}
