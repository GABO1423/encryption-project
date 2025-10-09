use actix_web::{App, HttpServer, HttpResponse, Responder, get, post, web, error::ErrorInternalServerError};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, LineEnding}, Pkcs1v15Encrypt};
use tokio::task;
use rand::rngs::OsRng;
use serde::Deserialize;
use base64::{engine::general_purpose, Engine as _};
//use sqlx::PgPool;
//use std::env;
use dotenvy::dotenv;
use aes_gcm::{aead::{Aead, KeyInit, consts::U12}, Aes256Gcm, Nonce};
use std::sync::{Arc, Mutex};

const URL: &str = "localhost";
const PORT: u16 = 8081;

// Struct usado para conocer los datos que se necesitan
// accesibles en cualquier momento, por ahora solo
//private_key. Option porque no será inicializado al inicio
struct AppState{
    private_key: Option<RsaPrivateKey>,
}

//Esta vaina no tiene clases, pero visualiza que el struct
// es una clase y esto el constructor :D
impl AppState{
    pub fn new() -> Self{
        AppState {private_key: None}
    }
}

type InitializationVector = Nonce<U12>;

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
    data: web::Data<Arc<Mutex<AppState>>>
) -> Result<impl Responder, actix_web::Error> 
{
    //desencriptación de b64
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

    //se obtiene la private_key, acceso posible por clonar
    //al mostrar como data obtenible en todos los endpoints
    //al crear el server
    let app_state = data.lock().unwrap();
    let decrypted_key = app_state.private_key.as_ref()
        .unwrap()
        .decrypt(Pkcs1v15Encrypt, &encrypted_key);
    
    //se transforma la llave para poder usarse
    let cipher = Aes256Gcm::new_from_slice(&decrypted_key.as_ref().unwrap());
    //nonce fijo harcodeado por pruebas
    let nonce = InitializationVector::from([69, 42, 13, 8, 5, 1, 69, 42, 13, 8, 5, 1]);

    //desencriptacion del archivo
    let decrypted_file = cipher.unwrap().decrypt(&nonce, encrypted_file.as_ref())
        .map_err(|e| ErrorInternalServerError(format!("Decryption failed: {}", e)))?;

    // se transforma el texto a string
    let decrypted_text = String::from_utf8(decrypted_file)
        .map_err(|e| ErrorInternalServerError(format!("Error decoding UTF-8: {}", e)))?;

    println!("File received and decoded: {}", json_data.filename);
    println!("encrypted file: {:?}", decrypted_text);
    //println!("encrypted key: {:?}",  decrypted_key.as_ref().unwrap());
    Ok(HttpResponse::Ok().body(format!("Data for '{}' received, decoded, and ready for decryption.", json_data.filename)))
}

#[get("/public-key")]
async fn get_public_key(data: web::Data<Arc<Mutex<AppState>>>) -> impl Responder
{
    println!("Generating new RSA key...");
    let (private_key, public_key) = generate_keys().await;
    //se guarda la private_key como variable global en servidor
    let mut app_state = data.lock().unwrap();
    app_state.private_key = Some(private_key);
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
    println!("Sending public key...\n");
    HttpResponse::Ok().content_type("application/x-pem-file").body(public_key_pem)
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    dotenv().ok();
    let server_address = format!("{}:{}", URL, PORT);
    println!("Key Server running at http://{}/public-key", server_address);

    /* SI NO COMPILA NO LO SUBAS POR EL AMOR A DIOS
    let database_url = env::var("DATABASE_URL")
    .expect("ERROR: The DATABASE_URL environment variable is not configured or could not be loaded.");

    println!("Connecting to the database...");
    let pool = match PgPool::connect(&database_url).await {
        Ok(p) => {
            println!("Connection successful.");
            p
        },
        Err(e) => {
            eprintln!("Error connecting to the database: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };

    /* EXAMPLE OF HOW TO USE IT
    let row: (i64,) = sqlx::query_as("SELECT 100")
        .fetch_one(&pool)
        .await?;
    */*/

    //instancia de la data a usar en los endpoints
    let app_state = web::Data::new(Arc::new(Mutex::new(AppState::new())));

    let server = HttpServer::new(move || {
        App::new()
            .service(get_public_key)
            .service(receive_data)
            .app_data(app_state.clone())
    }).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}