use serde_json::{self, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Result as IoResult};
use std::path::Path;

use json_value_ext::JsonValueExt;

pub fn load_folder_map<P: AsRef<Path>>(path: P) -> IoResult<BTreeMap<String, LockedFolder>> {
    let mut file = try!(File::open(path));
    let mut buf = String::new();
    try!(file.read_to_string(&mut buf));
    let json = strip_js(&buf);
    let v = serde_json::de::from_str(json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
    let v: serde_json::Value = try!(v);
    let mut map = BTreeMap::new();
    for (k, v) in v.as_object().expect("root must be object").iter() {
        map.insert((*k).clone(), LockedFolder {
            created: try!(v.retrieve("created", |v| v.as_u64())),
            overview: try!(v.retrieve("overview", |v| v.as_owned_string())),
            smart: v.retrieve("smart", |v| v.as_boolean()).unwrap_or(false),
            tx: try!(v.retrieve("tx", |v| v.as_u64())),
            updated: try!(v.retrieve("updated", |v| v.as_u64())),
            uuid: try!(v.retrieve("uuid", |v| v.as_owned_string())),
        });
    }
    Ok(map)
}

#[derive(Clone, Debug)]
pub struct LockedFolder {
    created: u64,
    overview: String,
    smart: bool,
    tx: u64,
    updated: u64,
    uuid: String,
}

fn strip_js(s: &str) -> &str {
    s.trim_left_matches("loadFolders(").trim_right_matches(");")
}
