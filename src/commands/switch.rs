use anyhow::{Context, Result, bail};
use claudectl::profile;

use crate::commands::use_profile;

pub fn run() -> Result<()> {
    let profiles = profile::list_profiles()?;
    if profiles.is_empty() {
        bail!("no profiles saved. Use 'claudectl save' or 'claudectl login <alias>'.");
    }
    let active = profile::get_active()?;

    let items: Vec<String> = profiles
        .iter()
        .map(|p| match p.meta.email() {
            Some(email) if email != p.meta.alias => format!("{} ({email})", p.meta.alias),
            _ => p.meta.alias.clone(),
        })
        .collect();
    let default = active
        .and_then(|a| profiles.iter().position(|p| p.meta.alias == a))
        .unwrap_or(0);

    let selection = dialoguer::FuzzySelect::new()
        .with_prompt("Switch to")
        .items(&items)
        .default(default)
        .interact()
        .context("no selection made (need a TTY; use 'claudectl use <alias>')")?;

    use_profile::run(Some(&profiles[selection].meta.alias))
}
