//! Google-Oauth
//!
//! A server-side google oauth2 verification library for rust.
//!
//! # Installation
//! This library is hosted on [crates.io](https://crates.io/crates/mysql_async/)
//!
//! ```toml
//! [dependencies]
//! google-oauth = "1"
//! ```
//!
//! # Usage
//! The Library provides API to verify `id_token` from Google.
//!
//! ## Example: Blocking
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
const GOOGLE_ISS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const DEFAULT_TIMEOUT: u64 = 5u64;
