use actix_web::{HttpResponse};
use actix_multipart::Multipart;
use futures::TryStreamExt;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use base64::{engine::general_purpose, Engine as _};
use bytes::BytesMut;
use super::{EncryptedTransferData, KeyResponse, URL_PUBLIC_KEY, URL_SEND_INFO};
use crate::encryption_helper::{generate_key, encrypt_file, encrypt_key};

pub async fn handle_upload(mut payload: Multipart) -> Result<HttpResponse, actix_web::Error> 
{
    let response = reqwest::get(URL_PUBLIC_KEY).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let key_response: KeyResponse = if response.status().is_success() {response.json().await.map_err(actix_web::error::ErrorInternalServerError)?}
    else
    {
        let status = response.status();
        eprintln!("Failed to get public key and transfer ID: {}", status);
        return Err(actix_web::error::ErrorInternalServerError(format!("Failed to get public key from receiver: {}", status)));
    };

    println!("Received public key and transfer ID successfully.");

    let parsed_public_key = RsaPublicKey::from_public_key_pem(&key_response.public_key_pem)
        .map_err(|e| {eprintln!("Error parsing RSA Public Key: {:?}", e);
    actix_web::error::ErrorInternalServerError("Invalid public key format received.")})?;

    let transfer_id = key_response.transfer_id;
    
    while let Some(mut field) = payload.try_next().await?
    {
        let filename = field.content_disposition().and_then(|cd| cd.get_filename())
            .map(|s| s.to_string()).unwrap_or_else(|| "unnamed_file".to_string());

        let mut buffer = BytesMut::new();
        while let Some(chunk) = field.try_next().await? {buffer.extend_from_slice(&chunk);}
        
        let file_data = buffer.freeze();
        println!("Received file: {}", filename);

        let (key, nonce) = generate_key();

        let encrypted_file = encrypt_file(&file_data, &key, &nonce).map_err(|e|
        {
            println!("Encryption error: {}", e);
            actix_web::error::ErrorInternalServerError("File encryption failed")
        })?;

        let encrypted_key = encrypt_key(&key, &parsed_public_key).map_err(|e|
        {
            println!("Key encryption error: {}", e);
            actix_web::error::ErrorInternalServerError("Key encryption failed")
        })?;
        
        let nonce_b64 = general_purpose::STANDARD.encode(nonce.as_slice());
        let encrypted_file_b64 = general_purpose::STANDARD.encode(&encrypted_file);
        let encrypted_key_b64 = general_purpose::STANDARD.encode(&encrypted_key);

        let transfer_data = EncryptedTransferData
        {
            encrypted_file_b64,
            encrypted_key_b64,
            filename: filename.clone(),
            nonce_b64,
            transfer_id: transfer_id.clone()
        };

        let client = reqwest::Client::new();
        let forward_response = client.post(URL_SEND_INFO).json(&transfer_data).send().await
            .map_err(actix_web::error::ErrorInternalServerError)?;

        if forward_response.status().is_success()
        {
            println!("Data successfully forwarded to {}", URL_SEND_INFO);
            return Ok(HttpResponse::Ok().body(format!("File '{}' processed and forwarded successfully.", filename)));
        }
        else
        {
            let status = forward_response.status();
            let text = forward_response.text().await.unwrap_or_else(|_| "No body received".to_string());
            eprintln!("Failed to forward data. Status: {}. Response: {}", status, text);
            return Err(actix_web::error::ErrorInternalServerError(format!("Failed to forward data to the receiver: {}", status)));
        }
    }
    Ok(HttpResponse::BadRequest().body("No files found in the request."))
}