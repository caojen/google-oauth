//!
//! # Google-Oauth
//!
//! ## Description
//! `Google-Oauth` is a server-side verification library for Google oauth2.
//!
//! `Google-Oauth` can help you to verify `id_token` or `access_token` which is generated from Google.
//!
//! ## Usage (async)
//!
//! ### 1. Setup
//! To import `Google-Oauth` to your project, please add this line into your `Cargo.toml`.
//!
//! ```toml
//! [dependencies]
//! google-oauth = { version = "1" }
//! ```
//!
//! If you decided to use `async` function, please select an `async` runtime. Here are some options for you:
//! 1. [tokio](https://github.com/tokio-rs/tokio)
//! 2. [async-std](https://github.com/async-rs/async-std)
//! 3. [actix-web](https://github.com/actix/actix-web)
//!
//! We use [tokio](https://github.com/tokio-rs/tokio) in our example, and refactor our main function like this:
//! ```rust
//! #[tokio::main]
//! // #[async_std::main] // when you use [async-std]
//! // #[actix_web::main] // when you use [actix-web]
//! async fn main() {}
//! ```
//!
//! ### 2. Do Verification (`id_token`)
//!
//! You can get your `client_id` from Google Admin Console (or somewhere else), and an `id_token` has been provided from
//! your user. They are all `string-like`. Use the following code to do verification:
//! ```rust
//! use google_oauth::AsyncClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client_id = "your client id";
//!     let id_token = "the id_token";
//!
//!     let client = AsyncClient::new(client_id);
//!     /// or, if you want to set the default timeout for fetching certificates from Google, e.g, 30 seconds, you can:
//!     /// ```rust
//!     /// let client = AsyncClient::new(client_id).timeout(time::Duration::from_sec(30));
//!     /// ```
//!
//!     let payload = client.validate_id_token(id_token).await.unwrap(); // In production, remember to handle this error.
//!
//!     // When we get the payload, that mean the id_token is valid.
//!     // Usually we use `sub` as the identifier for our user...
//!     println!("Hello, I am {}", &payload.sub);
//! }
//! ```
//!
//! ### 3. Do Verification (`AccessToken`)
//!
//! Sometimes, Google will return an `access_token` instead of `id_token`. `Google-Oauth` still provides API for validate
//! `access_token` from Google.
//!
//! Note: when validating `access_token`, we don't matter the `client_id`. So if you just need to validate `access_token`,
//! you can simply pass an empty `client_id`, just like this:
//!
//! ```rust
//! use google_oauth::AsyncClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let access_token = "the access_token";
//!
//!     let client = AsyncClient::new("");
//!
//!     let payload = client.validate_access_token(access_token).await.unwrap(); // In production, remember to handle this error.
//!
//!     // When we get the payload, that mean the id_token is valid.
//!     // Usually we use `sub` as the identifier for our user...
//!     println!("Hello, I am {}", &payload.sub);
//! }
//! ```
//!
//! Warning: the result of `access_token` is different from the result of `id_token`, although they have a same field `sub`.
//!
//! > Full example, please view ./example/async_client/
//!
//! ## Algorithm Supported
//! For validating `id_token`, Google may use these two kinds of hash algorithm to generate JWTs:
//!
//! - [x] RS256
//! - [ ] ES256
//!
//! However, I cannot find any approach to get a valid `ES256` token, and as a result, I remained a `unimplemented` branch,
//! and return an `Err` if the JWT is `ES256` hashed.
//!
//! Feel free to create a new issue if you have an example. PR is welcome.
//!
//! ## Usage (blocking)
//! `Google-Oauth` also provides a blocking client. You need to enable `blocking` feature:
//! ```toml
//! [dependencies]
//! google-oauth = { version = "1", features = ["blocking"] }
//! ```
//!
//! You can use `google_oauth::Client` to validate tokens:
//! ```rust
//! use google_oauth::Client;
//!
//! fn main() {
//!     let client_id = "your client id";
//!     let id_token = "the id_token";
//!
//!     let client = Client::new(client_id);
//!
//!     let payload = client.validate_id_token(id_token).unwrap();
//!
//!     println!("Hello, I am {}", &payload.sub);
//! }
//! ```
//!
//! > Full example, please view ./examples/blocking/
//!
//! ## WebAssembly (wasm)
//! `Google-Oauth` supports wasm, feature `wasm` is required.
//! ```toml
//! [dependencies]
//! google-oauth = { version = "1", features = ["wasm"] }
//! ```
//!
//! You can build this library with ``wasm-pack build --features wasm``. (`cargo install wasm-pack` to install first.)
//!
//! If you need to import `wasm` into your project, you can use `google_oauth::Client` to run async functions.
//!
//! ## Features
//! + `default`: enable `AsyncClient`.
//! + `blocking`: enable `Client`.
//! + `wasm`: disable `AsyncClient` and `Client`(`blocking`), enable `Client` (`wasm`).
//!

#[cfg(feature = "blocking")]
mod client;
#[cfg(not(feature = "wasm"))]
mod async_client;
mod output;

#[cfg(feature = "wasm")]
mod wasm;

mod jwt_parser;
#[cfg(not(feature = "wasm"))]
mod certs;
mod validate;
mod utils;

#[cfg(feature = "blocking")]
pub use client::*;
#[cfg(not(feature = "wasm"))]
pub use async_client::*;
#[cfg(not(feature = "wasm"))]
pub use certs::*;
pub use output::*;

#[cfg(feature = "wasm")]
pub use wasm::*;

#[allow(unused)]
const GOOGLE_SA_CERTS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
#[allow(unused)]
const GOOGLE_ISS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
#[allow(unused)]
const DEFAULT_TIMEOUT: u64 = 5u64;
#[allow(unused)]
const GOOGLE_OAUTH_V3_USER_INFO_API: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

#[cfg(all(feature = "wasm", feature = "blocking"))]
compile_error!("wasm and blocking are mutually exclusive and cannot be enabled together");
