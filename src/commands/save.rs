use anyhow::{Context, Result};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;

pub fn run(alias: Option<&str>) -> Result<()> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());

    let creds = store.read_credentials()?;
    let account = store.read_oauth_account()?;

    let alias = match alias {
        Some(a) => profile::validate_alias(a)?.to_string(),
        None => default_alias_from_account(account.as_ref())?,
    };

    let saved = profile::save_profile_to(&paths, &alias, &creds, account)?;
    // What we just saved IS the live login, so it is the active profile.
    profile::set_active_from(&paths, &alias)?;
    println!(
        "saved profile '{}' ({})",
        alias,
        saved.meta.email().unwrap_or("unknown")
    );
    Ok(())
}

fn default_alias_from_account(account: Option<&serde_json::Value>) -> Result<String> {
    account
        .and_then(|a| a.get("emailAddress"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .context("no email found in ~/.claude.json; pass an alias: claudectl save <alias>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_alias_comes_from_email() {
        let account = serde_json::json!({"emailAddress": "a@x"});
        assert_eq!(default_alias_from_account(Some(&account)).unwrap(), "a@x");
    }

    #[test]
    fn default_alias_errors_without_email() {
        assert!(default_alias_from_account(None).is_err());
        let no_email = serde_json::json!({"accountUuid": "u1"});
        assert!(default_alias_from_account(Some(&no_email)).is_err());
    }
}
