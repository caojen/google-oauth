# Google-Oauth

## Description
`Google-Oauth` is a server-side verification library for Google oauth2.

`Google-Oauth` can help you to verify `id_token` which is generated from Google.

This lib provides `blocking` and `async` API for your convince. If you are using `async`, note that 
`Google-Oauth` doesn't provide any async runtime (like `tokio` or `async-std`).

## Simple Usage

Suppose you've got an `id_token` from Google. `id_token` is a JWT which looks like `eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OTY5YWVjMzdhNzc4MGYxODgwNz...`.

And you need to know your `client_id` which you generated in Google Admin Console. The `client_id` looks like `xxxxx.apps.googleusercontent.com`.

Now, add this in your `Cargo.toml`:

```toml
[dependencies]
google-oauth = "1"
```

Then,
```rust

use google_oauth::Client;

fn main() {
    let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OTY5YWVjMzdhNzc4MGYxODgwNz..."; // this is the token we are going to verify
    let client_id = "xxxxx.apps.googleusercontent.com";
    
    let client = Client::new(client_id);
    
    let data = client.validate_id_token(id_token);
    
    match &data {
        Ok(data) => println!("ok: {:?}", data),
        Err(e) => println!("{:?}", e),
    };
    
    // now we got the data
    // usually we use the `sub` as a unique id for the user
    
    println!("user with sub: {} login!", data.unwrap().sub);
}
```

## AsyncClient
You can use `AsyncClient` with an async runtime.

```rust
use google_oauth::AsyncClient;

#[tokio::main]
// or #[async_std::main]
// or #[actix_web::main]
async fn main() {
    let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2OTY5YWVjMzdhNzc4MGYxODgwNz..."; // this is the token we are going to verify
    let client_id = "xxxxx.apps.googleusercontent.com";
    
    let client = AsyncClient::new(client_id);
    
    let data = client.validate_id_token(id_token).await;
    match &data {
        Ok(data) => println!("ok: {:?}", data),
        Err(e) => println!("{:?}", e),
    };
    
    // now we got the data
    // usually we use the `sub` as a unique id for the user
    
    println!("user with sub: {} login!", data.unwrap().sub);
}
```
