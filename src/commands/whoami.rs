use anyhow::Result;
use claudectl::config;
use claudectl::profile;

pub fn run() -> Result<()> {
    let paths = config::default_paths()?;
    match profile::get_active_from(&paths)? {
        Some(alias) => {
            let email = profile::get_profile_from(&paths, &alias)
                .ok()
                .and_then(|p| p.meta.email().map(str::to_string));
            match email {
                Some(email) if email != alias => println!("{alias} ({email})"),
                _ => println!("{alias}"),
            }
        }
        None => println!("no active profile"),
    }
    Ok(())
}
