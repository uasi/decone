use clap::{App, ArgMatches, SubCommand};
use rpassword;
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
                        .arg_from_usage("<folders.js>"))
            .subcommand(SubCommand::with_name("unlock-vault"));
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
            ("unlock-vault", Some(matches)) => {
                unlock_vault(matches);
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

fn unlock_vault<'n, 'a>(_matches: &ArgMatches<'n, 'a>) {
    use std::io::{self, Write};
    let locked_vault = op_vault::vault::LockedVault::new(get_sample_vault_path()).unwrap();
    print!("Enter password for sample vault: ");
    io::stdout().flush();
    let password = rpassword::read_password().unwrap();
    if locked_vault.unlock(&password).is_some() {
        println!("Unlocked");
    } else {
        println!("Failed to unlock");
    }
}

const DEFAULT_KEYCHAIN_PATH: &'static str = "Dropbox/1Password/1Password.agilekeychain";

fn get_default_keychain_path() -> PathBuf {
    env::home_dir().expect("HOME must be set").join(DEFAULT_KEYCHAIN_PATH)
}

const SAMPLE_VAULT_PATH: &'static str = "test/SampleVault.opvault";

fn get_sample_vault_path() -> PathBuf {
    let mut path = PathBuf::from(file!());
    path.pop();
    path.pop();
    path.push(SAMPLE_VAULT_PATH);
    path
}
