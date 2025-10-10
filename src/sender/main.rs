use actix_web::{web, App, HttpServer};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use actix_files::Files;
use serde::{Deserialize, Serialize};

pub const URL: &str = "localhost";
pub const PORT: u16 = 8080;
pub const URL_PUBLIC_KEY : &str = "http://localhost:8081/public-key";
pub const URL_SEND_INFO: &str = "http://localhost:8081/receive-data";
pub type InMemoryStorage = Arc<Mutex<HashMap<String, Vec<u8>>>>; 

mod encryption_helper;
mod file_management;

#[derive(Debug, Serialize)]
pub struct EncryptedTransferData
{
    pub encrypted_file_b64: String,
    pub encrypted_key_b64: String,
    pub filename: String,
    pub nonce_b64: String,
    pub transfer_id: String
}

#[derive(Debug, Deserialize)]
pub struct KeyResponse
{
    pub public_key_pem: String,
    pub transfer_id: String
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    let storage: InMemoryStorage = Arc::new(Mutex::new(HashMap::new()));
    let storage_data = web::Data::new(storage.clone());
    let server = HttpServer::new(move || {App::new().app_data(storage_data.clone()).route("/upload", web::post().to(file_management::handle_upload))
        .service(Files::new("/", "./src/sender/frontend").index_file("index.html"))}).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}