use actix_web::{web, HttpResponse, Responder, get, post, error::ErrorInternalServerError};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, LineEnding, EncodePrivateKey}};
use tokio::task;
use rand::rngs::OsRng;
use uuid::Uuid;
use base64::{engine::general_purpose, Engine as _};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use super::{AppState, IncomingTransferData, PublicKeyResponse, ENCRYPTED_FILES_DIR};

async fn generate_keys() -> (RsaPrivateKey, RsaPublicKey)
{
    let private_key = task::spawn_blocking(||
    {
        let mut rng = OsRng;
        let bits = 2048; 
        RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate keys")
    }).await.expect("Key generation task on the blocking thread failed");

    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

#[get("/public-key")]
pub async fn get_public_key(data: web::Data<AppState>) -> Result<impl Responder, actix_web::Error>
{
    println!("Generating new RSA key pair for transfer...");
    let (private_key, public_key) = generate_keys().await;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF).map_err(|e| ErrorInternalServerError(format!("Failed to encode public key: {}", e)))?;
    let private_key_der = private_key.to_pkcs8_der()
        .map_err(|e| ErrorInternalServerError(format!("Failed to encode private key to DER: {}", e)))?
        .as_bytes().to_vec();
        
    let transfer_id = Uuid::new_v4().to_string();
    {
        let mut key_cache = data.key_cache.lock().unwrap();
        key_cache.insert(transfer_id.clone(), private_key_der);
    }
    
    println!("Private key cached for transfer ID: {}", transfer_id);
    Ok(HttpResponse::Ok().json(PublicKeyResponse {public_key_pem,transfer_id,}))
}

#[post("/receive-data")]
pub async fn receive_data(json_data: web::Json<IncomingTransferData>, data: web::Data<AppState>) -> Result<impl Responder, actix_web::Error> 
{
    let transfer_id = &json_data.transfer_id;
    let private_key_der: Vec<u8>;
    {
        let mut key_cache = data.key_cache.lock().unwrap();
        private_key_der = key_cache.remove(transfer_id).ok_or_else(||
        {
            eprintln!("Error: Key not found for transfer ID {}", transfer_id);
            ErrorInternalServerError("Transfer session expired or key already used.")
        })?;
    }

    let encrypted_key_bytes = general_purpose::STANDARD.decode(&json_data.encrypted_key_b64)
        .map_err(|e| {eprintln!("Error decoding key: {:?}", e); ErrorInternalServerError("Invalid Base64 key.")})?;
    let encrypted_file_bytes = general_purpose::STANDARD.decode(&json_data.encrypted_file_b64)
        .map_err(|e| {eprintln!("Error decoding file: {:?}", e); ErrorInternalServerError("Invalid Base64 file.")})?;
    let nonce_bytes = general_purpose::STANDARD.decode(&json_data.nonce_b64)
        .map_err(|e| {eprintln!("Error decoding nonce: {:?}", e); ErrorInternalServerError("Invalid Base64 nonce.")})?;

    let unique_file_id = Uuid::new_v4().to_string();
    let file_path_on_disk = format!("{}/{}", ENCRYPTED_FILES_DIR, unique_file_id);
    
    match File::create(&file_path_on_disk).await
    {
        Ok(mut file) => 
        {
            if let Err(e) = file.write_all(&encrypted_file_bytes).await
            {
                eprintln!("Error writing file to disk: {}", e);
                data.key_cache.lock().unwrap().insert(transfer_id.clone(), private_key_der); 
                return Err(ErrorInternalServerError("Failed to write encrypted file to disk."));
            }
        },
        Err(e) => 
        {
            eprintln!("Error creating file on disk: {}", e);
            data.key_cache.lock().unwrap().insert(transfer_id.clone(), private_key_der); 
            return Err(ErrorInternalServerError("Failed to create encrypted file on disk."));
        }
    }

    let query_result = sqlx::query!(
        "INSERT INTO files (file_name, file_path, nonce_value, encrypted_key, private_key) VALUES ($1, $2, $3, $4, $5)",
        json_data.filename, file_path_on_disk, nonce_bytes, encrypted_key_bytes, private_key_der
    ).execute(&data.pool).await;
    
    if let Err(e) = query_result
    {
        eprintln!("Database insertion failed: {}", e);
        let _ = tokio::fs::remove_file(&file_path_on_disk).await;
        data.key_cache.lock().unwrap().insert(transfer_id.clone(), private_key_der); 
        return Err(ErrorInternalServerError(format!("Failed to store metadata in database. File deleted from disk: {}", e)));
    }
    
    println!("File received, stored on disk at: {}", file_path_on_disk);
    
    Ok(HttpResponse::Ok().body(format!("Data for '{}' received and stored.", json_data.filename)))
}