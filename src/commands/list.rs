use anyhow::Result;
use claudectl::profile;

pub fn run() -> Result<()> {
    let profiles = profile::list_profiles()?;
    if profiles.is_empty() {
        println!("no profiles saved. Use 'claudectl save' or 'claudectl login <alias>'.");
        return Ok(());
    }
    let active = profile::get_active()?;
    for p in profiles {
        let marker = if active.as_deref() == Some(p.meta.alias.as_str()) {
            "*"
        } else {
            " "
        };
        let label = p
            .meta
            .label
            .as_deref()
            .map(|label| format!(" [{label}]"))
            .unwrap_or_default();
        match p.meta.email() {
            Some(email) if email != p.meta.alias => {
                println!("{marker} {}{label} ({email})", p.meta.alias)
            }
            _ => println!("{marker} {}{label}", p.meta.alias),
        }
    }
    Ok(())
}
