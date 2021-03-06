#![allow(dead_code)] // until we release 0.1.0...

extern crate base64;
#[macro_use(crate_version)]
extern crate clap;
extern crate openssl;
extern crate rpassword;
extern crate serde_json;

mod agile_keychain;
mod cli;
mod json_value_ext;
mod op_vault;

use cli::Cli;

fn main() {
    Cli::new().run();
}
