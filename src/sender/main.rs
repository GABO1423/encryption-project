use actix::fut::ok;
use actix::Response;
use actix_web::{body, get, web, App, Error, HttpResponse, HttpServer, Responder};
use actix_multipart::Multipart;
use futures::TryStreamExt;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::file_management::InMemoryStorage;
use actix_files::Files;
use bytes::BytesMut;
use std::borrow::Cow;
use reqwest::Client;

mod file_management;
mod encryption_helper;

const URL: &str = "localhost";
const PORT: u16 = 8080;
const KEY_SERVER_URL : &str = "http://localhost:8081/public-key";

async fn handle_upload(mut payload: Multipart, storage: web::Data<InMemoryStorage>) -> Result<HttpResponse, actix_web::Error>
{
    let response = reqwest::get(KEY_SERVER_URL).await.map_err(actix_web::error::ErrorInternalServerError)?;

    let body = if response.status().is_success()
    {
        let public_key = response.text().await.map_err(actix_web::error::ErrorInternalServerError)?;
        println!("Public key: {}", public_key);
        public_key
    }
    else
    {
        println!("Failed: {}", response.status());
        String::new()
    };

    while let Some(mut field) = payload.try_next().await?
    {
        let filename = field.content_disposition().and_then(|cd| cd.get_filename())
            .map(|s| s.to_string()).unwrap_or_else(|| "unnamed_file".to_string());

        let mut buffer = BytesMut::new();
        while let Some(chunk) = field.try_next().await? {buffer.extend_from_slice(&chunk);}
        
        let file_data = buffer.freeze();
        println!("Received file: {}", filename);
        
        let content_display = if let Ok(s) = std::str::from_utf8(&file_data) {Cow::Borrowed(s)}
        else
        {
            let hex_preview = file_data.iter().take(30).map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ");
            Cow::Owned(format!("<Binary Content: {} bytes> Preview (Hex): {}", file_data.len(), hex_preview))
        };
        
        println!("File content:\n{}", content_display);
        
        let mut storage_lock = storage.lock().unwrap();
        storage_lock.insert(filename.clone(), file_data.to_vec());
        
        return Ok(HttpResponse::Ok().body(format!("File '{}' processed and stored.", filename)));
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