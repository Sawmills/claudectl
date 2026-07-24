use std::io::{self, Write};

use anyhow::{Context, Result};
use claudectl::api::{self, CredentialsFile};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::oauth;
use claudectl::profile;
use claudectl::shell;

pub fn run(alias: &str) -> Result<()> {
    let alias = profile::validate_alias(alias)?;
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    let flow = SystemLoginFlow {
        paths: &paths,
        store: &store,
    };
    run_with(alias, &flow)
}

fn run_with(alias: &str, flow: &dyn LoginFlow) -> Result<()> {
    // Before the browser and before any token exchange: a locked target Keychain
    // must not surface only after the user finished the whole OAuth dance.
    flow.ensure_keychain_ready()?;

    let pkce = oauth::generate_pkce();
    let state = oauth::generate_state();
    let url = oauth::build_authorize_url(&pkce.challenge, &state);

    println!("Opening browser for Claude login. If it doesn't open, visit:");
    println!();
    println!("  {url}");
    println!();
    flow.open_browser(&url);

    let input = flow.read_authorization_code()?;
    let (code, code_state) = oauth::parse_pasted_code(&input, &state);

    let creds_oauth = flow.exchange_code(code, code_state, &pkce.verifier)?;
    let account = flow.fetch_oauth_account(&creds_oauth.access_token);
    if account.is_none() {
        eprintln!("warning: could not fetch account identity; profile saved without it");
    }

    let creds = CredentialsFile {
        claude_ai_oauth: creds_oauth,
        extra: serde_json::Map::new(),
    };
    flow.save_profile(alias, &creds, account)?;
    let email = flow
        .activate(alias)
        .with_context(|| activation_failed_hint(alias))?;
    println!("logged in and switched to {alias} ({email})");
    Ok(())
}

trait LoginFlow {
    fn ensure_keychain_ready(&self) -> Result<()>;
    fn open_browser(&self, url: &str);
    fn read_authorization_code(&self) -> Result<String>;
    fn exchange_code(&self, code: &str, state: &str, verifier: &str) -> Result<api::OauthCreds>;
    fn fetch_oauth_account(&self, access_token: &str) -> Option<serde_json::Value>;
    fn save_profile(
        &self,
        alias: &str,
        creds: &CredentialsFile,
        account: Option<serde_json::Value>,
    ) -> Result<()>;
    fn activate(&self, alias: &str) -> Result<String>;
}

struct SystemLoginFlow<'a> {
    paths: &'a config::Paths,
    store: &'a AuthStore,
}

impl LoginFlow for SystemLoginFlow<'_> {
    fn ensure_keychain_ready(&self) -> Result<()> {
        self.store.ensure_keychain_ready()
    }

    fn open_browser(&self, url: &str) {
        let _ = open::that(url);
    }

    fn read_authorization_code(&self) -> Result<String> {
        print!("Paste the authorization code: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("failed to read authorization code")?;
        Ok(input)
    }

    fn exchange_code(&self, code: &str, state: &str, verifier: &str) -> Result<api::OauthCreds> {
        oauth::exchange_code(code, state, verifier)
    }

    fn fetch_oauth_account(&self, access_token: &str) -> Option<serde_json::Value> {
        api::fetch_oauth_account(access_token).unwrap_or(None)
    }

    fn save_profile(
        &self,
        alias: &str,
        creds: &CredentialsFile,
        account: Option<serde_json::Value>,
    ) -> Result<()> {
        profile::save_profile_to(self.paths, alias, creds, account)?;
        Ok(())
    }

    fn activate(&self, alias: &str) -> Result<String> {
        profile::switch_to(self.store, self.paths, alias)
    }
}

/// The profile is already on disk once activation runs, so the recovery is an
/// activation retry — never another OAuth round trip.
fn activation_failed_hint(alias: &str) -> String {
    let alias = shell::quote_arg(alias);
    format!(
        "login succeeded and the profile is saved, but activating it failed. \
         resolve the cause that follows, then run: claudectl use {alias} — \
         you do not need to log in again"
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Debug, PartialEq)]
    enum LoginEvent {
        Readiness,
        Browser,
        TokenExchange,
        Save,
        Activate,
    }

    struct FakeLoginFlow {
        events: RefCell<Vec<LoginEvent>>,
        readiness_fails: bool,
        activation_fails: bool,
    }

    impl FakeLoginFlow {
        fn ready() -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                readiness_fails: false,
                activation_fails: false,
            }
        }
    }

    impl LoginFlow for FakeLoginFlow {
        fn ensure_keychain_ready(&self) -> Result<()> {
            self.events.borrow_mut().push(LoginEvent::Readiness);
            if self.readiness_fails {
                anyhow::bail!("locked");
            }
            Ok(())
        }

        fn open_browser(&self, _url: &str) {
            self.events.borrow_mut().push(LoginEvent::Browser);
        }

        fn read_authorization_code(&self) -> Result<String> {
            Ok("code".to_string())
        }

        fn exchange_code(
            &self,
            _code: &str,
            _state: &str,
            _verifier: &str,
        ) -> Result<api::OauthCreds> {
            self.events.borrow_mut().push(LoginEvent::TokenExchange);
            Ok(api::OauthCreds {
                access_token: "access".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: None,
                scopes: Vec::new(),
                subscription_type: None,
                rate_limit_tier: None,
                extra: serde_json::Map::new(),
            })
        }

        fn fetch_oauth_account(&self, _access_token: &str) -> Option<serde_json::Value> {
            Some(serde_json::json!({"emailAddress": "work@x"}))
        }

        fn save_profile(
            &self,
            _alias: &str,
            _creds: &CredentialsFile,
            _account: Option<serde_json::Value>,
        ) -> Result<()> {
            self.events.borrow_mut().push(LoginEvent::Save);
            Ok(())
        }

        fn activate(&self, _alias: &str) -> Result<String> {
            self.events.borrow_mut().push(LoginEvent::Activate);
            if self.activation_fails {
                anyhow::bail!("activation denied");
            }
            Ok("work@x".to_string())
        }
    }

    #[test]
    fn keychain_readiness_precedes_browser_and_token_exchange() {
        let flow = FakeLoginFlow::ready();

        run_with("work@x", &flow).unwrap();

        assert_eq!(
            flow.events.into_inner(),
            vec![
                LoginEvent::Readiness,
                LoginEvent::Browser,
                LoginEvent::TokenExchange,
                LoginEvent::Save,
                LoginEvent::Activate,
            ]
        );
    }

    #[test]
    fn keychain_readiness_failure_prevents_browser_and_token_exchange() {
        let flow = FakeLoginFlow {
            readiness_fails: true,
            ..FakeLoginFlow::ready()
        };

        let err = run_with("work@x", &flow).unwrap_err().to_string();

        assert!(err.contains("locked"), "got: {err}");
        assert_eq!(flow.events.into_inner(), vec![LoginEvent::Readiness]);
    }

    #[test]
    fn activation_failure_points_at_claudectl_use_not_a_new_login() {
        let hint = activation_failed_hint("work account; $(id)");

        assert!(
            hint.contains("claudectl use 'work account; $(id)'"),
            "got: {hint}"
        );
        assert!(hint.contains("profile is saved"), "got: {hint}");
        assert!(hint.contains("do not need to log in again"), "got: {hint}");
    }

    #[test]
    fn activation_failure_chain_includes_recovery_command() {
        let flow = FakeLoginFlow {
            activation_fails: true,
            ..FakeLoginFlow::ready()
        };

        let err = run_with("work account", &flow).unwrap_err();

        assert!(
            format!("{err:#}").contains("claudectl use 'work account'"),
            "got: {err:#}"
        );
    }
}
