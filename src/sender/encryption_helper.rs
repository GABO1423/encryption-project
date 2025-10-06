use aes_gcm::{aead::{Aead, KeyInit, OsRng, consts::U12}, Aes256Gcm, Nonce};
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, errors::Error};
use rand::RngCore;
use std::error::Error as StdError;

type EncryptionKey = [u8; 32];
type InitializationVector = Nonce<U12>;

pub fn generate_key() -> (EncryptionKey, InitializationVector)
{
    let mut key_bytes: EncryptionKey = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = InitializationVector::from(nonce_bytes);
    (key_bytes, nonce)
}

pub fn encrypt_file(
    plaintext_data: &[u8], 
    key: &EncryptionKey, 
    nonce: &InitializationVector
) -> Result<Vec<u8>, Box<dyn StdError>>
{ 
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext_data).map_err(|_| {
        "Encryption failed internally"
    })?;
    
    println!("File encrypted successfully.");

    return Ok(ciphertext_with_tag)
}

pub fn encrypt_key(key: &EncryptionKey, public_key: &RsaPublicKey) -> Result<Vec<u8>, Error>
{
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, key)
}