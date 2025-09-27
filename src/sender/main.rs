use actix_web::{ App, HttpServer, HttpResponse, Error, get, Responder, web};
use actix_multipart::Multipart;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::{fs::File, io::Read, path::Path};

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

/*#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let storage: InMemoryStorage = Arc::new(Mutex::new(HashMap::new()));

    let server = HttpServer::new(move || {
        App::new()//.app algo xddd

    })
    .bind((URL, PORT))?;

    println!("Server running at http://{}:{}", URL, PORT);

    server.run().await
}*/