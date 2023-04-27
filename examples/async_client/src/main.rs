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
