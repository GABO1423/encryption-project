use actix_web::{web, App, HttpResponse, HttpServer};
use actix_multipart::Multipart;
use futures::TryStreamExt;
use rsa::pkcs8::DecodePublicKey;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::encryption_helper::{encrypt_file, encrypt_key, generate_key};
use crate::file_management::{InMemoryStorage};
use actix_files::Files;
use bytes::BytesMut;
use rsa::RsaPublicKey;
use serde::Serialize;
use base64::{engine::general_purpose, Engine as _};

mod file_management;
mod encryption_helper;

const URL: &str = "localhost";
const PORT: u16 = 8080;
const URL_PUBLIC_KEY : &str = "http://localhost:8081/public-key";
const URL_SEND_INFO: &str = "http://localhost:8081/receive-data";

#[derive(Debug, Serialize)]
struct EncryptedTransferData {
    encrypted_file_b64: String,
    encrypted_key_b64: String,
    filename: String,
}


async fn handle_upload(mut payload: Multipart, _storage: web::Data<InMemoryStorage>) -> Result<HttpResponse, actix_web::Error>
{
    let response = reqwest::get(URL_PUBLIC_KEY).await.map_err(actix_web::error::ErrorInternalServerError)?;

    let body = if response.status().is_success()
    {
        let public_key = response.text().await.map_err(actix_web::error::ErrorInternalServerError)?;
        println!("received public key successfully.");
        public_key
    }
    else
    {
        println!("Failed: {}", response.status());
        String::new()
    };

    let parsed_public_key = RsaPublicKey::from_public_key_pem(&body)
        .map_err(|e| {
            eprintln!("Error parsing RSA Key: {:?}", e);
            actix_web::error::ErrorInternalServerError("Invalid public key format received.")
       })?;


    while let Some(mut field) = payload.try_next().await?
    {
        let filename = field.content_disposition().and_then(|cd| cd.get_filename())
            .map(|s| s.to_string()).unwrap_or_else(|| "unnamed_file".to_string());

        let mut buffer = BytesMut::new();
        while let Some(chunk) = field.try_next().await? {buffer.extend_from_slice(&chunk);}
        
        let file_data = buffer.freeze();
        println!("Received file: {}", filename);

        //let mut storage_lock = storage.lock().unwrap();
        //storage_lock.insert(filename.clone(), file_data.to_vec());
        //drop(storage_lock);

        let (_key, _nonce) = generate_key();

        let encrypted_file = encrypt_file(&file_data, &_key, &_nonce).map_err(|e| {
            println!("Encryption error: {}", e);
            actix_web::error::ErrorInternalServerError("File encryption failed")
        })?;

        let encrypted_key = encrypt_key(&_key, &parsed_public_key).map_err(|e| {
            println!("Key encryption error: {}", e);
            actix_web::error::ErrorInternalServerError("Key encryption failed")
        })?;
        
        println!("Encrypted file size: {:?}", encrypted_file);
        println!("Encrypted key size: {:?}", encrypted_key);

        let encrypted_file_b64 = general_purpose::STANDARD.encode(&encrypted_file);
        let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);

        let transfer_data = EncryptedTransferData {
            encrypted_file_b64,
            encrypted_key_b64,
            filename: filename.clone(),
        };

        let client = reqwest::Client::new();
        let forward_response = client.post(URL_SEND_INFO)
            .json(&transfer_data)
            .send()
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?;

        if forward_response.status().is_success() {
            println!("Data successfully forwarded to {}", URL_SEND_INFO);
            return Ok(HttpResponse::Ok().body(format!("File '{}' processed and forwarded successfully.", filename)));
        } else {
            let status = forward_response.status();
            let text = forward_response.text().await.unwrap_or_else(|_| "No body received".to_string());
            eprintln!("Failed to forward data. Status: {}. Response: {}", status, text);
            return Err(actix_web::error::ErrorInternalServerError(format!("Failed to forward data to the key server: {}", status)));
        }

        
        // Helper to see what in the data on the file.
        // if let Err(e) = view_file_content(&filename, &storage) {
        //    println!("Error viewing file content: {}", e);
        // }
    }
    Ok(HttpResponse::BadRequest().body("No files found in the request."))
}

#[actix_web::main]
async fn main() -> std::io::Result<()>
{
    let storage: InMemoryStorage = Arc::new(Mutex::new(HashMap::new()));
    let storage_data = web::Data::new(storage.clone());
    let server = HttpServer::new(move || {
        App::new().app_data(storage_data.clone()).route("/upload", web::post().to(handle_upload))
        .service(Files::new("/", "./src/sender/frontend").index_file("index.html"))}).bind((URL, PORT))?;

    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);
    server.run().await
}