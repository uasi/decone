use serde_json;

use std::fs;
use std::io::{self, Result as IoResult};
use std::path::{Path, PathBuf};

const FILES_DIR_REL_PATH: &'static str = "a/default/files";

#[derive(Clone, Debug)]
pub struct Archive {
    entries: Vec<ArchiveEntry>,
}

impl Archive {
    pub fn with_keychain_path<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        let mut path_buf = path.as_ref().to_path_buf();
        path_buf.push(FILES_DIR_REL_PATH);
        Archive::new(&path_buf)
    }

    pub fn attachments(&self) -> Vec<Attachment> {
        self.entries.iter().flat_map(|entry| entry.attachments.iter().cloned()).collect()
    }

    fn new(path: &Path) -> IoResult<Self> {
        let mut entries = Vec::new();
        for dir_entry in try!(fs::read_dir(path)) {
            let dir_entry = try!(dir_entry);
            if try!(fs::metadata(dir_entry.path())).is_dir() {
                entries.push(try!(ArchiveEntry::new(&dir_entry.path())));
            }
        }
        Ok(Archive { entries: entries })
    }
}

#[derive(Clone, Debug)]
pub struct ArchiveEntry {
    uuid: String,
    attachments: Vec<Attachment>,
}

impl ArchiveEntry {
    fn new(path: &Path) -> IoResult<Self> {
        let uuid = path.file_name().expect("file name must not be empty").to_string_lossy().into_owned();
        let mut attachments = Vec::new();
        for dir_entry in try!(fs::read_dir(path)) {
            let dir_entry = try!(dir_entry);
            if try!(fs::metadata(dir_entry.path())).is_file() && dir_entry.path().extension() == None {
                attachments.push(try!(Attachment::new(&dir_entry.path())));
            }
        }
        Ok(ArchiveEntry {
            uuid: uuid,
            attachments: attachments,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Attachment {
    uuid: String,
    path: PathBuf,
    metadata: Metadata,
}

impl Attachment {
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn new(path: &Path) -> IoResult<Self> {
        let uuid = path.file_name().expect("file name must not be empty").to_string_lossy().into_owned();
        let metadata = try!(Metadata::new(&Attachment::get_metadata_file_path(path)));
        Ok(Attachment {
            uuid: uuid,
            path: path.to_path_buf(),
            metadata: metadata,
        })
    }

    fn get_metadata_file_path(path: &Path) -> PathBuf {
        let mut path_buf = path.to_path_buf();
        path_buf.set_extension("def");
        path_buf
    }
}

#[derive(Clone, Debug)]
pub struct Metadata {
    encryption_key_uuid: String,
    file_name: String,
    encrypted: bool,
}

impl Metadata {
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    fn new(path: &Path) -> IoResult<Self> {
        let file = try!(fs::File::open(path));
        let value = serde_json::de::from_reader(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        let value: serde_json::Value = try!(value);

        Ok(Metadata {
            encryption_key_uuid: try!(value.retrieve("encryptionKey", |v| v.as_owned_string())),
            file_name: try!(value.retrieve("filename", |v| v.as_owned_string())),
            encrypted: try!(value.retrieve("encrypted", |v| v.as_boolean())),

        })
    }
}

trait JsonValueExt {
    fn as_owned_string(&self) -> Option<String>;
    fn retrieve<T, F>(&self, key: &str, mapper: F) -> IoResult<T>
        where F: FnOnce(&serde_json::Value) -> Option<T>;
}

impl JsonValueExt for serde_json::Value {
    fn as_owned_string(&self) -> Option<String> {
        self.as_string().and_then(|s| Some(s.to_string()))
    }

    fn retrieve<T, F>(&self, key: &str, mapper: F) -> IoResult<T>
        where F: FnOnce(&serde_json::Value) -> Option<T>
    {
        self
            .find(key)
            .and_then(|value| mapper(value))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("could not retrieve {}", key))
            })
    }
}
