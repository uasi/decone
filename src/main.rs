#[macro_use(crate_version)]
extern crate clap;
extern crate serde_json;

mod agile_keychain;
mod cli;

use cli::Cli;

fn main() {
    Cli::new().run();
}
