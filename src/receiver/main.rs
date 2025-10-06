use actix_web::{web, App, HttpServer, HttpResponse, Responder, get};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
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
async fn get_public_key() -> impl Responder
{
    println!("Generating new RSA key...");

    let mut private_key = generate_keys_asynchronously().await;
    //let mut private_key_pem_string = private_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).expect("Fallo la privada");
    let mut public_key = RsaPublicKey::from(&private_key);
    let mut public_key_pem_string = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
    //let shared_public_key_pem: SharedPublicKeyPem = Arc::new(public_key_pem_string.clone());

    println!("{:?}",private_pem);
    println!("Sending public key...\n");
    HttpResponse::Ok().content_type("application/x-pem-file").body(public_key_pem_string)
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    let server_address = format!("{}:{}", URL, PORT);
    println!("Key Server running at http://{}/public-key", server_address);

    let server = HttpServer::new(move || {App::new()
        .service(get_public_key)}).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}