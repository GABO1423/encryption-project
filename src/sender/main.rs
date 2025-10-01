use actix_web::{ App, HttpServer, HttpResponse, Error, get, Responder, web};
use actix_multipart::Multipart;
use futures::TryStreamExt;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::file_management::InMemoryStorage;
use actix_files::Files;
use bytes::BytesMut;
use std::borrow::Cow;

mod file_management;
mod encryption_helper;

const URL: &str = "localhost";
const PORT: u16 = 8080;

// Ejemplo de uso:
/*#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let storage_map: HashMap<String, Vec<u8>> = HashMap::new();
    let storage_arc_mutex = Arc::new(Mutex::new(storage_map));
    let storage_data = actix_web::web::Data::new(storage_arc_mutex);

    let local_path = Path::new("C:/Users/moraz/Documents/Programming/Computing Security/encryption-project/src/sender/test.txt"); 
    println!("Attempting to upload local file: {:?}", local_path);

    match file_management::upload_local_file(local_path, &storage_data) {
        Ok(filename) => {
            println!("\nUpload successful: {}", filename);
            
            println!("--- Retrieving Content from Memory ---");
            
            match file_management::view_file_content(&filename, &storage_data) {
                Ok(content) => {
                    println!("Content of '{}':\n", filename);
                    println!("{}", content);
                },
                Err(e) => {
                    eprintln!("Error viewing content: {}", e);
                    
                    let storage_lock = storage_data.lock().unwrap();
                    if let Some(data) = storage_lock.get(&filename) {
                        eprintln!("(Data is present, total size: {} bytes, but not valid UTF-8 text.)", data.len());
                    }
                }
            }
            println!("--------------------------------------\n");
        },
        Err(e) => {
            eprintln!("\nError during local file upload: {}", e);
            eprintln!("Ensure the path is correct and the file exists.");
        }
    }

    Ok(())
}
*/

async fn handle_upload(
    mut payload: Multipart,
    storage: web::Data<InMemoryStorage>,
) -> Result<HttpResponse, actix_web::Error> {
    
    while let Some(mut field) = payload.try_next().await? {
        let filename = field.content_disposition()
            .and_then(|cd| cd.get_filename())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unnamed_file".to_string());

        let mut buffer = BytesMut::new();
        
        while let Some(chunk) = field.try_next().await? {
            buffer.extend_from_slice(&chunk);
        }
        
        let file_data = buffer.freeze();
        
        println!("Received file name: {}", filename);
        
        let content_display = if let Ok(s) = std::str::from_utf8(&file_data) {
            Cow::Borrowed(s)
        } else {
            let hex_preview = file_data.iter().take(30).map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ");
            Cow::Owned(format!("<Binary Content: {} bytes> Preview (Hex): {}", file_data.len(), hex_preview))
        };
        
        println!("File content:\n{}", content_display);
        
        let mut storage_lock = storage.lock().unwrap();
        storage_lock.insert(filename.clone(), file_data.to_vec());
        
        return Ok(HttpResponse::Ok().body(format!("File '{}' processed and stored.", filename)));
    }
    
    Ok(HttpResponse::BadRequest().body("No file parts found in the request."))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let storage: InMemoryStorage = Arc::new(Mutex::new(HashMap::new()));
    let storage_data = web::Data::new(storage.clone());
    let server = HttpServer::new(move || {
        App::new()
            .app_data(storage_data.clone())
            .route("/upload", web::post().to(handle_upload))
            .service(
                Files::new("/", "./src/sender/frontend") 
                    .index_file("index.html")
            )
    })
    .bind((URL, PORT))?;

    // a clear because i cant see all the shit throwing at once.
    clearscreen::clear().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    println!("Server running at http://{}:{}", URL, PORT);

    server.run().await
}