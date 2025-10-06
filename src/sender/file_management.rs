use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub type InMemoryStorage = Arc<Mutex<HashMap<String, Vec<u8>>>>;

pub fn view_file_content(filename: &str, storage: &InMemoryStorage) -> Result<String, String> {
    let storage_lock = storage.lock().map_err(|_| "Failed to lock storage mutex".to_string())?;
    if let Some(file_data) = storage_lock.get(filename) {
        match str::from_utf8(file_data) {
            Ok(text) => {
                let preview = if text.len() > 50 {
                    format!("{}...", &text[..50])
                } else {
                    text.to_string()
                };
                println!("Storage Check: File '{}' content preview ({} bytes): '{}'", filename, file_data.len(), preview);
                return Ok(text.to_string())
            },
            Err(e) => {
                let error_msg = format!("Error translating file data to UTF-8. This file is likely binary or non-text. ({})", e);
                println!("Error: {}", error_msg);
                return Err(error_msg)
            }
        }
    } else {
        let error_msg = format!("file '{}' does not exist in storage.", filename);
        println!("Error: {}", error_msg);
        return Err(error_msg)
    }
}