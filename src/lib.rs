//! Google-Oauth
//!
//! A server-side google oauth2 verification library for rust.
//!
//! # Installation
//! This library is hosted on [crates.io](https://crates.io/crates/google-oauth/)
//!
//! ```toml
//! [dependencies]
//! google-oauth = "1"
//! ```
//!
//! # Usage of `id_token`
//! The Library provides API to verify `id_token` from Google.
//!
//! ## Example: Async
//! ```rust
//! // When you use async client, remember to add a async runtime (e.g, `tokio` or `async_std`)
//! use google_oauth::AsyncClient; // This is a async client
//!
//! // It works just like the blocking client, excepts the verification step.
//!
//! #[tokio::main]
//! async fn main() {
//!     let client_id = "...";
//!     let client = AsyncClient::new(client_id);
//!
//!     /// note: use `await`
//!     let data = client.validate_id_token("The id_token you want to validate").await.unwrap();
//!
//!     // it `unwrap()` is ok, we get the data ...
//!     println!("Hello, user (sub = {}) now is online", sub);
//! }
//! ```
//!
//! ## Example: Blocking
//!
//! Note: if you want to use blocking client, you need to enable `blocking` feature:
//! > By default, `blocking` feature is disabled.
//! ```toml
//! [dependencies]
//! google-oauth = { version = "1", features = "blocking" }
//! ```
//!
//! ```rust
//! // With blocking client, we don't need async runtime.
//! use google_oauth::Client; // This is a blocking client
//!
//! let client_id = "The client_id generated from google...";
//! let client = Client::new(client_id); // now we get this.
//!
//! let data = client.validate_id_token("The id_token you want to validate").unwrap();
//!
//! // if ok, we get the data...
//! let sub = data.sub.as_str();
//! println!("Hello, user (sub = {}) now is online", sub);
//! ```
//!
//! # Usage of `access_token`
//!
//! Please use api [`Client::validate_access_token`] or [`AsyncClient::validate_access_token`] instead.
//!

#[cfg(feature = "blocking")]
mod client;
mod async_client;
mod output;
mod jwt_parser;
mod certs;
mod validate;
mod utils;

#[cfg(feature = "blocking")]
pub use client::*;
pub use async_client::*;
pub use output::*;

const GOOGLE_SA_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const DEFAULT_TIMEOUT: u64 = 5u64;

const GOOGLE_OAUTH_V3_USER_INFO_API: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
