use clap::{App, ArgMatches, SubCommand};
use std::env;
use std::path::PathBuf;

use agile_keychain::attachment;

pub struct Cli;

impl Cli {
    pub fn new() -> Self {
        Cli
    }

    pub fn run(&self) {
        let crate_version = crate_version!();
        let app = App::new("decone")
            .version(&crate_version)
            .subcommand(SubCommand::with_name("export-attachments")
                        .arg_from_usage("-u --uuid=<uuid>"))
            .subcommand(SubCommand::with_name("list-attachments"));
        match app.get_matches_lossy().subcommand() {
            ("export-attachments", Some(matches)) => {
                export_attachments(matches);
            }
            ("list-attachments", Some(matches)) => {
                list_attachments(matches);
            }
            _ => {}
        }
    }
}

fn export_attachments<'n, 'a>(_matches: &ArgMatches<'n, 'a>) {
    println!("Not yet implemented");
}

fn list_attachments<'n, 'a>(_matches: &ArgMatches<'n, 'a>) {
    let archive = attachment::Archive::with_keychain_path(get_default_keychain_path());
    for attachment in archive.attachments() {
        println!("{} {}", attachment.uuid(), attachment.metadata().file_name());
    }
}

const DEFAULT_KEYCHAIN_PATH: &'static str = "Dropbox/1Password/1Password.agilekeychain";

fn get_default_keychain_path() -> PathBuf {
    env::home_dir().expect("HOME must be set").join(DEFAULT_KEYCHAIN_PATH)
}
