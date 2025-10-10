use actix_web::{web, HttpResponse, Responder, get, delete, error::{ErrorInternalServerError, ErrorNotFound}};
use rsa::{RsaPrivateKey, pkcs8::{DecodePrivateKey}, Pkcs1v15Encrypt};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm};
use tokio::io::AsyncReadExt;
use tokio::fs::File;
use mime_guess;
use super::{AppState, FileRecord, FileDecryptionData, InitializationVector};

async fn get_and_decrypt_file_data(pool: &sqlx::PgPool, file_id: i64) -> Result<(Vec<u8>, FileDecryptionData), actix_web::Error>
{
    let record: FileDecryptionData = sqlx::query_as!(FileDecryptionData,
        "SELECT file_name, file_path, encrypted_key, nonce_value, private_key FROM files WHERE id_file = $1", 
        file_id).fetch_optional(pool).await.map_err(|e| ErrorInternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| ErrorNotFound(format!("File with ID {} not found.", file_id)))?;

    let private_key = RsaPrivateKey::from_pkcs8_der(&record.private_key)
        .map_err(|e| {eprintln!("Error parsing Private Key from DB: {}", e);
    ErrorInternalServerError("Internal error: Failed to parse stored private key.")})?;

    let decrypted_aes_key = private_key.decrypt(Pkcs1v15Encrypt, &record.encrypted_key)
        .map_err(|_| ErrorInternalServerError("AES Key decryption failed: Invalid key or padding."))?;

    let mut encrypted_file_content = Vec::new();
    let mut file = File::open(&record.file_path).await.map_err(|e|
    {
        eprintln!("Disk file error ({}): {}", record.file_path, e);
        ErrorInternalServerError("Encrypted file not found on disk or read error.")
    })?;
    
    file.read_to_end(&mut encrypted_file_content).await
        .map_err(|e| ErrorInternalServerError(format!("Failed to read file from disk: {}", e)))?;
    let cipher = Aes256Gcm::new_from_slice(&decrypted_aes_key)
        .map_err(|_| ErrorInternalServerError("Cipher init failed: Invalid AES key size."))?;
    let nonce_array: [u8; 12] = record.nonce_value.clone().try_into()
        .map_err(|_| ErrorInternalServerError("Invalid nonce size in database."))?;
    let nonce = InitializationVector::from(nonce_array);
    let decrypted_file = cipher.decrypt(&nonce, encrypted_file_content.as_ref())
        .map_err(|_| ErrorInternalServerError("File Decryption failed: Invalid tag or key."))?;
    Ok((decrypted_file, record))
}

#[get("/api/files")]
pub async fn list_files(data: web::Data<AppState>) -> Result<impl Responder, actix_web::Error>
{
    let files = sqlx::query_as!(FileRecord, "SELECT id_file, file_name FROM files ORDER BY id_file DESC").fetch_all(&data.pool).await
        .map_err(|e| ErrorInternalServerError(format!("Database query failed: {}", e)))?;
    Ok(HttpResponse::Ok().json(files))
}

#[get("/text_preview/{file_id}")]
pub async fn text_preview_file(path: web::Path<i32>, data: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error>
{
    let file_id: i64 = path.into_inner() as i64;
    let (decrypted_file, _) = get_and_decrypt_file_data(&data.pool, file_id).await?;
    let preview_text = String::from_utf8(decrypted_file).unwrap_or_else(|_| "File content is binary and cannot be displayed as text. Use download to retrieve the original file.".to_string());
    Ok(HttpResponse::Ok().content_type("text/plain; charset=utf-8").body(preview_text))
}

#[get("/stream/{file_id}")]
pub async fn stream_file(path: web::Path<i32>, data: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error>
{
    let file_id: i64 = path.into_inner() as i64;
    let (decrypted_file, record) = get_and_decrypt_file_data(&data.pool, file_id).await?;
    let content_type = mime_guess::from_path(&record.file_name).first_or_octet_stream().to_string();
    Ok(HttpResponse::Ok().content_type(content_type).body(decrypted_file))
}

#[get("/download/{file_id}")]
pub async fn download_file(path: web::Path<i32>, data: web::Data<AppState>) -> Result<impl Responder, actix_web::Error>
{
    let file_id: i64 = path.into_inner() as i64;
    let (decrypted_file, record) = get_and_decrypt_file_data(&data.pool, file_id).await?;
    let content_type = mime_guess::from_path(&record.file_name).first_or_octet_stream().to_string();
    Ok(HttpResponse::Ok().content_type(content_type).insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", record.file_name))).body(decrypted_file))
}

#[delete("/delete/{file_id}")] 
pub async fn delete_file(path: web::Path<i32>, data: web::Data<AppState>) -> Result<impl Responder, actix_web::Error>
{
    let file_id: i64 = path.into_inner() as i64;
    let record = sqlx::query!("SELECT file_path FROM files WHERE id_file = $1", file_id).fetch_optional(&data.pool).await.map_err(|e| ErrorInternalServerError(format!("Database query failed: {}", e)))?
        .ok_or_else(|| ErrorNotFound(format!("File with ID {} not found.", file_id)))?;
    let file_path_on_disk = record.file_path;

    if let Err(e) = sqlx::query!("DELETE FROM files WHERE id_file = $1", file_id).execute(&data.pool).await
    {
        eprintln!("Database deletion failed for file ID {}: {}", file_id, e);
        return Err(ErrorInternalServerError(format!("Failed to delete file metadata from database: {}", e)));
    }
    if let Err(e) = tokio::fs::remove_file(&file_path_on_disk).await {eprintln!("Disk file deletion failed for {}: {}", file_path_on_disk, e);}

    println!("File ID {} successfully deleted (DB record and disk file).", file_id);
    Ok(HttpResponse::Ok().body("File deleted successfully."))
}