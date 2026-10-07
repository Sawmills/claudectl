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
    /// Set or clear a profile's display label
    Label {
        /// Profile alias to label
        alias: String,
        /// Label text (omit or leave blank to clear)
        text: Option<String>,
    },
    /// Run one command on a saved profile without switching the live login
    Exec {
        /// Saved profile to run on (never the active profile)
        #[arg(long)]
        profile: String,
        /// Refuse unless the profile's accountUuid equals this value
        #[arg(long)]
        expect_account: Option<String>,
        /// Refuse unless the resolved executable has this SHA-256
        #[arg(long)]
        expect_sha256: Option<String>,
        /// Minimum token lifetime left before the run starts (e.g. 30m, 900s)
        #[arg(long, default_value = "30m", value_parser = claudectl::exec::parse_duration)]
        min_valid: std::time::Duration,
        /// Append JSON receipt records here (default: stderr)
        #[arg(long)]
        receipt: Option<std::path::PathBuf>,
        /// Program and arguments, after `--`
        #[arg(last = true, required = true)]
        command: Vec<std::ffi::OsString>,
    },
    /// Write a launcher script pinned to one saved profile and one executable
    Launcher {
        /// Saved profile the launcher runs on
        #[arg(long)]
        profile: String,
        /// Executable the launcher runs (for example the claude binary)
        #[arg(long)]
        claude: std::path::PathBuf,
        /// Where to write the launcher
        #[arg(long)]
        out: std::path::PathBuf,
        /// Minimum token lifetime passed to `exec`
        #[arg(long, default_value = "30m", value_parser = claudectl::exec::parse_duration)]
        min_valid: std::time::Duration,
    },
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
        Commands::Label {
            ref alias,
            ref text,
        } => commands::label::run(alias, text.as_deref()),
        Commands::Exec {
            profile,
            expect_account,
            expect_sha256,
            min_valid,
            receipt,
            mut command,
        } => {
            let program = command.remove(0);
            std::process::exit(commands::exec::run(claudectl::exec::ExecRequest {
                alias: profile,
                expect_account,
                expect_sha256,
                min_valid,
                receipt,
                program,
                args: command,
            }))
        }
        Commands::Launcher {
            ref profile,
            ref claude,
            ref out,
            min_valid,
        } => commands::launcher::run(profile, claude, out, min_valid),
        Commands::Completions { shell } => commands::completions::run(shell),
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
