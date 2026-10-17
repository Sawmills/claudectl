//! One launch settings file, shared by initial launches and supervised restarts.
use super::*;
use std::ffi::OsString;

pub(super) struct LaunchSettings {
    pub args: Vec<OsString>,
    user: Value,
    supplied: bool,
}

impl LaunchSettings {
    /// Consume explicit settings before any account token is acquired.
    pub fn parse(args: &[OsString]) -> Result<Self> {
        let mut parsed = Self {
            args: Vec::new(),
            user: json!({}),
            supplied: false,
        };
        let mut remaining = args.iter();
        while let Some(arg) = remaining.next() {
            if arg == "--" {
                parsed.args.push(arg.clone());
                parsed.args.extend(remaining.cloned());
                break;
            }
            let value = if arg == "--settings" {
                remaining
                    .next()
                    .context("--settings needs a JSON object or file path")?
                    .clone()
            } else if arg.as_encoded_bytes().starts_with(b"--settings=") {
                arg.to_str()
                    .context(
                        "--settings= needs valid UTF-8; use --settings <path> for other paths",
                    )?
                    .strip_prefix("--settings=")
                    .context("missing --settings= prefix")?
                    .into()
            } else {
                parsed.args.push(arg.clone());
                continue;
            };
            let user = read(&value)?;
            parsed.supplied = true;
            merge_settings(&mut parsed.user, user)?;
        }
        Ok(parsed)
    }

    /// Compose once per session directory so renewal never appends duplicate hooks.
    pub fn write(&self, dir: &Path, hooks: Option<&Path>) -> Result<Option<PathBuf>> {
        if hooks.is_none() && !self.supplied {
            return Ok(None);
        }
        let mut settings = match hooks {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => json!({}),
        };
        merge_settings(&mut settings, self.user.clone())?;
        let path = dir.join("hooks.json");
        atomic(&path, &settings)?;
        Ok(Some(path))
    }
}

fn read(value: &std::ffi::OsStr) -> Result<Value> {
    let inline = value.to_str().is_some_and(|s| {
        let s = s.trim_start();
        matches!(s.chars().next(), Some('{' | '[' | '"'))
            || serde_json::from_str::<Value>(s).is_ok()
    });
    let source = if inline {
        Path::new("inline --settings")
    } else {
        Path::new(value)
    };
    let bytes = if inline {
        value.as_encoded_bytes().to_vec()
    } else {
        std::fs::read(source).map_err(|error| {
            anyhow::anyhow!(
                "cannot read --settings file {} ({})",
                source.display(),
                error.kind()
            )
        })?
    };
    let settings: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("cannot parse --settings JSON from {}", source.display()))?;
    if !settings.is_object() {
        bail!(
            "--settings must contain a JSON object ({})",
            source.display()
        );
    }
    if let Some(hooks) = settings.get("hooks") {
        let hooks = hooks
            .as_object()
            .context("--settings hooks must be an object of event arrays")?;
        if hooks.values().any(|entries| !entries.is_array()) {
            bail!("--settings hook events must be arrays; generated hooks cannot be replaced");
        }
    }
    if settings.get("disableAllHooks") == Some(&Value::Bool(true)) {
        bail!("--settings cannot disable claudectl supervision hooks");
    }
    crate::exec::check_settings_value(&settings, source).map_err(|e| {
        anyhow::anyhow!("{e}\nTry: remove credential and routing overrides from --settings")
    })?;
    Ok(settings)
}

fn merge_settings(base: &mut Value, incoming: Value) -> Result<()> {
    let base = base
        .as_object_mut()
        .context("generated settings must be a JSON object")?;
    let Value::Object(incoming) = incoming else {
        bail!("--settings must be a JSON object");
    };
    for (key, value) in incoming {
        let hooks = key == "hooks";
        merge(base.entry(key).or_insert(Value::Null), value, hooks);
    }
    Ok(())
}

fn merge(base: &mut Value, incoming: Value, hooks: bool) {
    match (base, incoming) {
        (Value::Object(base), Value::Object(incoming)) => {
            for (key, value) in incoming {
                merge(base.entry(key).or_insert(Value::Null), value, hooks);
            }
        }
        (Value::Array(base), Value::Array(mut incoming)) if hooks => base.append(&mut incoming),
        (base, incoming) => *base = incoming,
    }
}
