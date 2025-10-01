use rsa::{RsaPrivateKey, pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
use tokio::task;
use rand::rngs::OsRng;


async fn generate_keys_asynchronously() -> RsaPrivateKey {
    task::spawn_blocking(|| {
        let mut rng = OsRng;
        let bits = 2048; 
        RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate keys")
    })
    .await
    .expect("Key generation task on the blocking thread failed")
}

#[tokio::main]
async fn main() {
    println!("🔑 Asynchronously generating a new 2048-bit RSA key pair...");

    let private_key = generate_keys_asynchronously().await;

    let public_key = private_key.to_public_key();

    println!("\n Keys generated successfully!\n");

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF).expect("Failed to encode private key to PEM");
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");



    println!("----------------------------------------------------");
    println!("               Private Key (PEM Format)          ");
    println!("----------------------------------------------------");

    println!("{:#?}", private_key_pem);
    
    

    println!("\n----------------------------------------------------");
    println!("                Public Key (PEM Format)           ");
    println!("----------------------------------------------------");
    println!("{}", public_key_pem);
}