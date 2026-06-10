use std::io::{self, Write};

use anyhow::{Context, Result};
use claudectl::api::{self, CredentialsFile};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::oauth;
use claudectl::profile;

pub fn run(alias: &str) -> Result<()> {
    let alias = profile::validate_alias(alias)?;
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());

    let pkce = oauth::generate_pkce();
    let state = oauth::generate_state();
    let url = oauth::build_authorize_url(&pkce.challenge, &state);

    println!("Opening browser for Claude login. If it doesn't open, visit:");
    println!();
    println!("  {url}");
    println!();
    let _ = open::that(&url);

    print!("Paste the authorization code: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read authorization code")?;
    let (code, code_state) = oauth::parse_pasted_code(&input, &state);

    let creds_oauth = oauth::exchange_code(code, code_state, &pkce.verifier)?;
    let account = api::fetch_oauth_account(&creds_oauth.access_token).unwrap_or(None);
    if account.is_none() {
        eprintln!("warning: could not fetch account identity; profile saved without it");
    }

    let creds = CredentialsFile {
        claude_ai_oauth: creds_oauth,
        extra: serde_json::Map::new(),
    };
    profile::save_profile_to(&paths, alias, &creds, account)?;
    let email = profile::switch_to(&store, &paths, alias)?;
    println!("logged in and switched to {alias} ({email})");
    Ok(())
}
