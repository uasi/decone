use serde_json;

use std::fs;
use std::path::{Path, PathBuf};

const FILES_DIR_REL_PATH: &'static str = "a/default/files";

#[derive(Clone, Debug)]
pub struct Archive {
    entries: Vec<ArchiveEntry>,
}

impl Archive {
    pub fn with_keychain_path<P: AsRef<Path>>(path: P) -> Self {
        let mut path_buf = path.as_ref().to_path_buf();
        path_buf.push(FILES_DIR_REL_PATH);
        Archive::new(&path_buf)
    }

    pub fn attachments(&self) -> Vec<Attachment> {
        self.entries.iter().flat_map(|entry| entry.attachments.iter().cloned()).collect()
    }

    fn new(path: &Path) -> Self {
        let mut entries = Vec::new();
        for dir_entry in fs::read_dir(path).unwrap() {
            let dir_entry = dir_entry.unwrap();
            if fs::metadata(dir_entry.path()).unwrap().is_dir() {
                entries.push(ArchiveEntry::new(&dir_entry.path()));
            }
        }
        Archive { entries: entries }
    }
}

#[derive(Clone, Debug)]
pub struct ArchiveEntry {
    uuid: String,
    attachments: Vec<Attachment>,
}

impl ArchiveEntry {
    fn new(path: &Path) -> Self {
        let uuid = path.file_name().expect("file name must not be empty").to_string_lossy().into_owned();
        let mut attachments = Vec::new();
        for dir_entry in fs::read_dir(path).unwrap() {
            let dir_entry = dir_entry.unwrap();
            if fs::metadata(dir_entry.path()).unwrap().is_file() && dir_entry.path().extension() == None {
                attachments.push(Attachment::new(&dir_entry.path()));
            }
        }
        ArchiveEntry {
            uuid: uuid,
            attachments: attachments,
        }
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

    fn new(path: &Path) -> Self {
        let uuid = path.file_name().expect("file name must not be empty").to_string_lossy().into_owned();
        let metadata = Metadata::new(&Attachment::get_metadata_file_path(path));
        Attachment {
            uuid: uuid,
            path: path.to_path_buf(),
            metadata: metadata,
        }
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

    fn new(path: &Path) -> Self {
        let file = fs::File::open(path).expect("file must be readable");
        let value: serde_json::Value = serde_json::de::from_reader(file).expect("file must be readable");
        Metadata {
            encryption_key_uuid: value.find("encryptionKey").unwrap().as_string().unwrap().into(),
            file_name: value.find("filename").unwrap().as_string().unwrap().into(),
            encrypted: value.find("encrypted").unwrap().as_boolean().unwrap(),
        }
    }
}
