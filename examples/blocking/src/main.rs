use google_oauth::Client;

fn main() {
    let client_id = "your client id";
    let id_token = "the id_token";

    let client = Client::new(client_id);

    let payload = client.validate_id_token(id_token).unwrap();

    println!("Hello, I am {}", &payload.sub);
}
