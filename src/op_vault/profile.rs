use serde_json::{self, Value};
use std::fs::File;
use std::io::{self, Read, Result as IoResult};
use std::path::Path;

use json_value_ext::JsonValueExt;
use op_vault::op_data_01::OpData01;

#[derive(Clone, Debug)]
pub struct LockedProfile {
    created_at: u64,
    iterations: u64,
    last_updated_by: String,
    master_key: OpData01,
    overview_key: OpData01,
    profile_name: String,
    salt: String,
    updated_at: u64,
    uuid: String,
}

impl LockedProfile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        let mut file = try!(File::open(path));
        let mut buf = String::new();
        try!(file.read_to_string(&mut buf));
        let json = strip_js(&buf);
        let v = serde_json::de::from_str(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        let v: serde_json::Value = try!(v);
        Ok(LockedProfile {
            created_at: try!(v.retrieve("createdAt", |v| v.as_u64())),
            iterations: try!(v.retrieve("iterations", |v| v.as_u64())),
            last_updated_by: try!(v.retrieve("lastUpdatedBy", |v| v.as_owned_string())),
            master_key: try!(v.retrieve("masterKey", |v| v.as_op_data_01())),
            overview_key: try!(v.retrieve("overviewKey", |v| v.as_op_data_01())),
            profile_name: try!(v.retrieve("profileName", |v| v.as_owned_string())),
            salt: try!(v.retrieve("salt", |v| v.as_owned_string())),
            updated_at: try!(v.retrieve("updatedAt", |v| v.as_u64())),
            uuid: try!(v.retrieve("uuid", |v| v.as_owned_string())),
        })
    }
}

fn strip_js(s: &str) -> &str {
    s.trim_left_matches("var profile=").trim_right_matches(";")
}

#[cfg(test)]
mod tests {
    use super::LockedProfile;

    fn get_profile_file_path() -> &'static str {
        "test/SampleVault.opvault/default/profile.js"
    }

    #[test]
    fn test_from_file() {
        let profile = LockedProfile::from_file(get_profile_file_path());
        assert!(profile.is_ok());
    }
}
