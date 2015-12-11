use std::io::{Result as IoResult};
use std::path::{Path, PathBuf};

use op_vault::profile::{LockedProfile, Profile};
use op_vault::key::{DerivedKey, Key, MainKey};

const PROFILE_REL_PATH: &'static str = "default/profile.js";

pub struct LockedVault {
    path: PathBuf,
    profile: LockedProfile,
}

impl LockedVault {
    pub fn new<P: AsRef<Path>>(path: P) -> IoResult<LockedVault> {
        load_locked_profile(path.as_ref())
            .and_then(|profile| {
                Ok(LockedVault {
                    path: path.as_ref().to_path_buf(),
                    profile: profile,
                })
            })
    }

    pub fn unlock(&self, password: &str) -> Option<Vault> {
        self.profile.unlock(password).and_then(|profile| {
            Some(Vault {
                path: self.path.clone(),
                profile: profile,
            })
        })
    }
}

pub struct Vault {
    path: PathBuf,
    profile: Profile,
}

fn load_locked_profile(path: &Path) -> IoResult<LockedProfile> {
    let mut path = path.to_path_buf();
    path.push(PROFILE_REL_PATH);
    println!("Loading {:?}", path);
    LockedProfile::from_file(path)
}
