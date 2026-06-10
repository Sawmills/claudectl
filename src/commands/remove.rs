use anyhow::Result;
use claudectl::config;
use claudectl::profile;

pub fn run(alias: &str) -> Result<()> {
    let paths = config::default_paths()?;
    let was_active = profile::get_active_from(&paths)?.as_deref() == Some(alias);
    profile::delete_profile_from(&paths, alias)?;
    if was_active {
        profile::clear_active_from(&paths)?;
        eprintln!("warning: removed the active profile; the live Claude Code login is untouched");
    }
    println!("removed profile '{alias}'");
    Ok(())
}
