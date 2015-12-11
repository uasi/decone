use serde_json;
use std::io::{self, Result as IoResult};

use op_vault::op_data_01::OpData01;

pub trait JsonValueExt {
    fn as_op_data_01(&self) -> Option<OpData01>;
    fn as_owned_string(&self) -> Option<String>;
    fn retrieve<T, F>(&self, key: &str, mapper: F) -> IoResult<T>
        where F: FnOnce(&serde_json::Value) -> Option<T>;
}

impl JsonValueExt for serde_json::Value {
    fn as_op_data_01(&self) -> Option<OpData01> {
        self.as_string().and_then(|s| OpData01::from_base64_str(s))
    }

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
