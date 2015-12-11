use clap::{App, ArgMatches, SubCommand};
use std::env;
use std::path::PathBuf;

use agile_keychain::attachment;
use op_vault;

pub struct Cli;

impl Cli {
    pub fn new() -> Self {
        Cli
    }

    pub fn run(&self) {
        let crate_version = crate_version!();
        let app = App::new("decone")
            .version(&crate_version)
            .subcommand(SubCommand::with_name("dump-profile")
                        .arg_from_usage("<profile.js>"))
            .subcommand(SubCommand::with_name("export-attachments")
                        .arg_from_usage("-u --uuid=<uuid>"))
            .subcommand(SubCommand::with_name("list-attachments"))
            .subcommand(SubCommand::with_name("list-folders")
                        .arg_from_usage("<folders.js>"));
        match app.get_matches_lossy().subcommand() {
            ("dump-profile", Some(matches)) => {
                dump_profile(matches);
            }
            ("export-attachments", Some(matches)) => {
                export_attachments(matches);
            }
            ("list-attachments", Some(matches)) => {
                list_attachments(matches);
            }
            ("list-folders", Some(matches)) => {
                list_folders(matches);
            }
            _ => {}
        }
    }
}

fn dump_profile<'n, 'a>(matches: &ArgMatches<'n, 'a>) {
    if let Some(path) = matches.value_of("profile.js") {
        let profile = op_vault::profile::LockedProfile::from_file(path);
        println!("{:?}", profile);
    }
}

fn export_attachments<'n, 'a>(_matches: &ArgMatches<'n, 'a>) {
    println!("Not yet implemented");
}

fn list_attachments<'n, 'a>(_matches: &ArgMatches<'n, 'a>) {
    match attachment::Archive::with_keychain_path(get_default_keychain_path()) {
        Ok(archive) => {
            for attachment in archive.attachments() {
                println!("{} {}", attachment.uuid(), attachment.metadata().file_name());
            }
        }
        Err(e) => {
            println!("{:?}", e);
        }
    }
}

fn list_folders<'n, 'a>(matches: &ArgMatches<'n, 'a>) {
    if let Some(path) = matches.value_of("folders.js") {
        match op_vault::folder::load_folder_map(path) {
            Ok(map) => {
                for folder in map.values() {
                    println!("{:?}", folder);
                }
            }
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }
}

const DEFAULT_KEYCHAIN_PATH: &'static str = "Dropbox/1Password/1Password.agilekeychain";

fn get_default_keychain_path() -> PathBuf {
    env::home_dir().expect("HOME must be set").join(DEFAULT_KEYCHAIN_PATH)
}
