use google_oauth::AsyncClient;

#[tokio::main]
async fn main() {
    let client_id = "your client id";
    let id_token = "the id_token";

    let client = AsyncClient::new(client_id);
    // or, if you want to set the default timeout for fetching certificates from Google, e.g, 30 seconds, you can:
    // ```rust
    // let client = AsyncClient::new(client_id).timeout(time::Duration::from_sec(30));
    // ```

    let payload = client.validate_id_token(id_token).await.unwrap(); // In production, remember to handle this error.

    // When we get the payload, that mean the id_token is valid.
    // Usually we use `sub` as the identifier for our user...
    println!("Hello, I am {}", &payload.sub);

    // if you have multiple client_ids, you can:
    let client = AsyncClient::new_with_vec(vec![client_id]);
    let payload = client.validate_id_token(id_token).await.unwrap();
    println!("Hello, I am {}", &payload.sub);
}
