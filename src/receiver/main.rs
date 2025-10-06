use actix_web::{App, HttpServer, HttpResponse, Responder, get};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, LineEnding}};
use tokio::task;
use rand::rngs::OsRng;

const URL: &str = "localhost";
const PORT: u16 = 8081;

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

#[get("/public-key")]
async fn get_public_key() -> impl Responder
{
    println!("Generating new RSA key...");

    // is _private_key because rn it's unused, delete the first _ when it's going to be used
    let (_private_key, public_key) = generate_keys().await;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
    //let shared_public_key_pem: SharedPublicKeyPem = Arc::new(public_key_pem_string.clone());
    
    /*let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).expect("Fallo la privada");
    println!("{:?}",private_pem);*/
    println!("Sending public key...\n");
    HttpResponse::Ok().content_type("application/x-pem-file").body(public_key_pem)
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