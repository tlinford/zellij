use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Default, Debug, Clone)]
#[structopt(name = "zellij")]
pub struct CliArgs {
    /// Maximum panes on screen, caution: opening more panes will close old ones
    #[structopt(long)]
    pub max_panes: Option<usize>,

    /// Path to a layout yaml file
    #[structopt(short, long)]
    pub layout: Option<PathBuf>,

    #[structopt(subcommand)]
    pub config: Option<ConfigCli>,

    #[structopt(short, long)]
    pub debug: bool,
}

#[derive(Debug, StructOpt, Clone)]
pub enum ConfigCli {
    /// Path to the configuration yaml file
    #[structopt(alias = "c")]
    Config {
        path: Option<PathBuf>,
        #[structopt(long)]
        /// Disables loading of configuration file at default location
        clean: bool,
    },
}
