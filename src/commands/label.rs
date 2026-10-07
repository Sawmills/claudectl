use anyhow::Result;
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;

pub fn run(alias: &str, text: Option<&str>) -> Result<()> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    match profile::set_label_from(&paths, &store, alias, text)? {
        Some(label) => println!("labelled '{alias}' as '{label}'"),
        None => println!("cleared the label of '{alias}'"),
    }
    Ok(())
}
