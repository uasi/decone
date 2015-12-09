use clap::{App, ArgMatches, SubCommand};

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
    println!("Not yet implemented");
}
