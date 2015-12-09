#[macro_use(crate_version)]
extern crate clap;

mod cli;

use cli::Cli;

fn main() {
    Cli::new().run();
}
