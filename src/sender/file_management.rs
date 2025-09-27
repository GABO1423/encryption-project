use std::{fs::File, io::Read, path::Path};
use actix_web::web::Data;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

type InMemoryStorage = Arc<Mutex<HashMap<String, Vec<u8>>>>;

pub fn upload_local_file(
    file_path: &Path,
    storage: &Data<InMemoryStorage>,
) -> Result<String, std::io::Error> {
    let filename = file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid file path or cannot get filename",
            )
        })?
        .to_string();

    let mut file = File::open(file_path)?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;

    let mut storage_lock = storage.lock().unwrap();
    storage_lock.insert(filename.clone(), file_data);

    Ok(filename)
}

pub fn view_file_content(
    filename: &str,
    storage: &Data<InMemoryStorage>,
) -> Result<String, String> {
    let storage_lock = storage.lock().unwrap();

    if let Some(file_data) = storage_lock.get(filename) {
        match str::from_utf8(file_data) {
            Ok(text) => Ok(text.to_string()),
            Err(e) => Err(format!(
                "Error translating: UTF-8 invalid. ({})",
                e
            )),
        }
    } else {
        Err(format!("Error: file '{}' not exists.", filename))
    }
}