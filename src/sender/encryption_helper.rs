use aes_gcm::{aead::{Aead, KeyInit, OsRng, consts::U12}, Aes256Gcm, Nonce};
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, errors::Error};
use rand::RngCore;
use std::{fs, io};

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

pub fn encrypt_file(input_filepath: &str, key: &EncryptionKey, nonce: &InitializationVector) -> io::Result<()>
{
    let plaintext = fs::read(input_filepath)?;
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext_with_tag = match cipher.encrypt(nonce, plaintext.as_ref())
    {
        Ok(c) => c,
        Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "Encryption failed internally",))
    };

    let output_filepath = format!("{}.enc", input_filepath);
    let mut final_output_content = Vec::with_capacity(nonce.len() + ciphertext_with_tag.len());

    final_output_content.extend_from_slice(nonce);
    final_output_content.extend_from_slice(&ciphertext_with_tag);

    fs::write(&output_filepath, final_output_content)?;
    Ok(())
}

pub fn encrypt_key(key: &EncryptionKey, public_key: &RsaPublicKey) -> Result<Vec<u8>, Error>
{
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, key)
}