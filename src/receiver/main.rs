use actix_web::{App, HttpServer, HttpResponse, Responder, get, post, web};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, LineEnding}};
use tokio::task;
use rand::rngs::OsRng;
use serde::Deserialize;
use base64::{engine::general_purpose, Engine as _};

const URL: &str = "localhost";
const PORT: u16 = 8081;



#[derive(Debug, Deserialize)]
struct IncomingTransferData {
    encrypted_file_b64: String,
    encrypted_key_b64: String,
    filename: String,
}

async fn generate_keys() -> (RsaPrivateKey, RsaPublicKey)
{
    let private_key = task::spawn_blocking(||
    {
        let mut rng = OsRng;
        let bits = 2048; 
        RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate keys")
    })
    .await.expect("Key generation task on the blocking thread failed");

    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

#[post("/receive-data")]
async fn receive_data(
    json_data: web::Json<IncomingTransferData>,
) -> Result<impl Responder, actix_web::Error> 
{
    let encrypted_key = general_purpose::STANDARD
        .decode(&json_data.encrypted_key_b64)
        .map_err(|e| {
            eprintln!("Error decoding key: {:?}", e);
            actix_web::error::ErrorBadRequest("Invalid Base64 key.") 
        })?;

    let encrypted_file = general_purpose::STANDARD
        .decode(&json_data.encrypted_file_b64)
        .map_err(|e| {
            eprintln!("Error decoding file: {:?}", e);
            actix_web::error::ErrorBadRequest("Invalid Base64 file.")
        })?;
    
    println!("File received and decoded: {}", json_data.filename);
    println!("encrypted file: {:?}", encrypted_file);
    println!("encrypted key: {:?}",  encrypted_key);
    Ok(HttpResponse::Ok().body(format!("Data for '{}' received, decoded, and ready for decryption.", json_data.filename)))
}

#[get("/public-key")]
async fn get_public_key() -> impl Responder
{
    println!("Generating new RSA key...");
    let (_private_key, public_key) = generate_keys().await;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
    println!("Sending public key...\n");
    HttpResponse::Ok().content_type("application/x-pem-file").body(public_key_pem)
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    let server_address = format!("{}:{}", URL, PORT);
    println!("Key Server running at http://{}/public-key", server_address);

    let server = HttpServer::new(move || {
        App::new()
            .service(get_public_key)
            .service(receive_data)
    }).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}