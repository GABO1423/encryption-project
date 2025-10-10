use actix_web::{web, App, HttpServer};
use sqlx::{PgPool, FromRow, Error as SqlxError};
use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use aes_gcm::{aead::{consts::U12}, Nonce};
use std::env;

const URL: &str = "localhost";
const PORT: u16 = 8081;
pub const ENCRYPTED_FILES_DIR: &str = "./src/receiver/encrypted_files";

mod encryption_helper;
mod file_management;

#[derive(Debug, FromRow, Serialize)]
pub struct FileRecord {pub id_file: i64, pub file_name: String}
#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {pub public_key_pem: String, pub transfer_id: String}
#[derive(Debug, Deserialize)]
pub struct IncomingTransferData
{ 
    pub encrypted_file_b64: String, pub encrypted_key_b64: String, 
    pub filename: String, pub nonce_b64: String, pub transfer_id: String 
}

#[derive(Debug, FromRow)]
pub struct FileDecryptionData
{
    pub file_name: String, pub file_path: String, pub encrypted_key: Vec<u8>, 
    pub nonce_value: Vec<u8>, pub private_key: Vec<u8>
}

pub type InitializationVector = Nonce<U12>;
pub struct AppState {pub pool: PgPool, pub key_cache: Mutex<HashMap<String, Vec<u8>>>}

async fn connect_db() -> Result<PgPool, SqlxError>
{
    let database_url = env::var("DATABASE_URL").expect("ERROR: The DATABASE_URL environment variable is not configured or could not be loaded.");
    match PgPool::connect(&database_url).await
    {
        Ok(p) =>
        {
            println!("Database connection successful.");
            Ok(p)
        }
        Err(e) =>
        {
            eprintln!("Error connecting to the database: {}", e);
            Err(e)
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    dotenvy::dotenv().ok();
    let pool = connect_db().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let app_data = web::Data::new(AppState {pool, key_cache: Mutex::new(HashMap::new()),});
    let server = HttpServer::new(move ||
    {
        App::new().app_data(app_data.clone()).app_data(web::JsonConfig::default().limit(15_728_640)) 
            .service(encryption_helper::get_public_key).service(encryption_helper::receive_data)
            .service(file_management::list_files).service(file_management::text_preview_file).service(file_management::stream_file)
            .service(file_management::download_file).service(file_management::delete_file)
            .service(actix_files::Files::new("/", "./src/receiver/frontend").index_file("index.html")) 
    }).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}