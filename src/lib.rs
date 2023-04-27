extern crate core;

mod client;
mod async_client;
mod output;
mod jwt_parser;
mod certs;
mod validate;

pub use client::*;
pub use async_client::*;
pub use output::*;
pub use jwt_parser::*;
pub use certs::*;

const GOOGLE_SA_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISS: &str = "https://accounts.google.com";
const DEFAULT_TIMEOUT: u64 = 5u64;
