mod commands;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use claudectl::config;

#[derive(Parser)]
#[command(
    name = "claudectl",
    version,
    about = "Manage multiple Claude Code accounts"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show account status and what to do next
    Status {
        /// Check only this saved profile
        alias: Option<String>,
        /// Use saved usage data without network requests or token refresh
        #[arg(long, conflicts_with = "refresh")]
        cached: bool,
        /// Refresh recent data, while still obeying saved cooldowns
        #[arg(long)]
        refresh: bool,
        /// Show token expiry, old usage data, and fetch diagnostics
        #[arg(long)]
        details: bool,
    },
    /// Log into a Claude account via OAuth and save it as a profile
    Login {
        /// Profile alias to save the login as
        alias: String,
    },
    /// Save the current live Claude Code login as a profile
    Save {
        /// Custom alias (defaults to email)
        alias: Option<String>,
    },
    /// Switch to a profile by alias (or most available if omitted)
    Use {
        /// Profile alias to switch to (auto-selects most available if omitted)
        alias: Option<String>,
    },
    /// Interactive fuzzy picker to switch accounts
    Switch,
    /// List saved profiles
    List,
    /// Remove a saved profile
    Remove {
        /// Profile alias to remove
        alias: String,
    },
    /// Show current active account
    Whoami,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

fn main() {
    // Parse first so --help and --version work without a writable home.
    let cli = Cli::parse();

    if let Err(e) = config::ensure_dirs() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }

    let result = match cli.command {
        Commands::Status {
            ref alias,
            cached,
            refresh,
            details,
        } => commands::status::run(
            alias.as_deref(),
            if cached {
                claudectl::usage_cache::FetchMode::Cached
            } else if refresh {
                claudectl::usage_cache::FetchMode::Refresh
            } else {
                claudectl::usage_cache::FetchMode::Normal
            },
            details,
        ),
        Commands::Login { ref alias } => commands::login::run(alias),
        Commands::Save { ref alias } => commands::save::run(alias.as_deref()),
        Commands::Use { ref alias } => commands::use_profile::run(alias.as_deref()),
        Commands::Switch => commands::switch::run(),
        Commands::List => commands::list::run(),
        Commands::Remove { ref alias } => commands::remove::run(alias),
        Commands::Whoami => commands::whoami::run(),
        Commands::Completions { shell } => commands::completions::run(shell),
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
