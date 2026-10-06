//! Account server for one company user's Claude subscription accounts.
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use claudectl::server::{app, engine::Endpoints, vault};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "claudectl-server",
    version,
    about = "Account server: keeps Claude refresh grants, gives machines access tokens"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create empty registries and, when absent, a new vault key
    Setup {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Check a local server's readiness without credentials
    HealthCheck {
        #[arg(long, default_value = "127.0.0.1:8787")]
        address: SocketAddr,
    },
    /// List company users, or enable or disable one by email
    Users {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, requires = "state")]
        email: Option<String>,
        #[arg(long, conflicts_with = "disable", requires = "email")]
        enable: bool,
        #[arg(long, conflicts_with = "enable", requires = "email")]
        disable: bool,
    },
    /// Revoke a machine
    Revoke {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        machine: String,
    },
    /// Decrypt and print the audit log
    Audit {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Serve the HTTP API
    Serve {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        /// The HTTPS origin machines use
        #[arg(long)]
        public_url: String,
        /// Company OIDC settings: issuer, client_id, client_secret_file, allowed_domains
        #[arg(long)]
        sso_config: Option<PathBuf>,
        /// Company email that may use this server; repeat for more
        #[arg(long = "allow-user", required = true)]
        allowed_users: Vec<String>,
        /// File that holds the Prometheus scrape token
        #[arg(long)]
        metrics_token_file: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Setup { state, key_file } => app::setup(&state, &key_file)?,
        Commands::HealthCheck { address } => {
            ensure!(address.ip().is_loopback(), "health checks require loopback");
            let response = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(3))
                .build()?
                .get(format!("http://{address}/ready"))
                .send()
                .await?;
            ensure!(
                response.status().is_success(),
                "account server is not ready"
            );
        }
        Commands::Users {
            state,
            email,
            enable,
            disable,
        } => match email {
            Some(email) if enable || disable => app::set_user(&state, &email, enable)?,
            _ => {
                for user in vault::users(&state)? {
                    println!("{} {} {}", user.id, user.email, user.enabled);
                }
            }
        },
        Commands::Revoke { state, machine } => app::revoke(&state, &machine)?,
        Commands::Audit { state, key_file } => {
            for event in claudectl::server::audit::read(&state, &key_file)? {
                println!("{event}");
            }
        }
        Commands::Serve {
            state,
            key_file,
            listen,
            public_url,
            sso_config,
            allowed_users,
            metrics_token_file,
        } => {
            claudectl::central::origin(&public_url).or_else(|_| {
                // A loopback test server may use plain HTTP.
                reqwest::Url::parse(&public_url)
                    .ok()
                    .filter(|_| listen.ip().is_loopback())
                    .context("public URL must be an HTTPS origin")
            })?;
            let metrics_token_hash = metrics_token_file
                .map(|path| -> Result<String> {
                    let token = String::from_utf8(vault::private_read(&path)?)?;
                    ensure!(!token.trim().is_empty(), "metrics token is empty");
                    Ok(vault::digest(token.trim().as_bytes()))
                })
                .transpose()?;
            let sso = sso_config.map(|config| app::Sso {
                config,
                public_url: public_url.clone(),
            });
            let config = app::Config {
                state,
                key: key_file,
                allowed_users,
                sso,
                metrics_token_hash,
                endpoints: Endpoints::default(),
            };
            app::serve(config, listen).await?;
        }
    }
    Ok(())
}
