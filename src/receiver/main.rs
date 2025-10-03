use actix_web::{web, App, HttpServer, HttpResponse, Responder, get};
use rsa::{RsaPrivateKey, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
use tokio::task;
use rand::rngs::OsRng;
use std::sync::Arc;

type SharedPublicKeyPem = Arc<String>;

const URL: &str = "localhost";
const PORT: u16 = 8081;

async fn generate_keys_asynchronously() -> RsaPrivateKey
{
    task::spawn_blocking(||
    {
        let mut rng = OsRng;
        let bits = 2048; 
        RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate keys")
    })
    .await.expect("Key generation task on the blocking thread failed")
}

#[get("/public-key")]
async fn get_public_key(public_key: web::Data<SharedPublicKeyPem>) -> impl Responder
{
    print!("Sending public key...\n");
    HttpResponse::Ok().content_type("application/x-pem-file").body(public_key.to_string())
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    println!("Generating new RSA key...");

    let private_key = generate_keys_asynchronously().await;
    let public_key = private_key.to_public_key();
    let public_key_pem_string = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
    let shared_public_key_pem: SharedPublicKeyPem = Arc::new(public_key_pem_string.clone());

    println!("Keys generated and Public Key ({} bytes) stored.", public_key_pem_string.len());

    let server_address = format!("{}:{}", URL, PORT);
    println!("Key Server running at http://{}/public-key", server_address);

    let server = HttpServer::new(move || {App::new().app_data(web::Data::new(shared_public_key_pem.clone()))
        .service(get_public_key)}).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}