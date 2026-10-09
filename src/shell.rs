/// Quote one argument for safe copy-paste into a POSIX shell.
pub fn quote_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// One argument as a user would type it: plain when a POSIX shell keeps it as one word
/// and runs nothing, quoted otherwise.
pub fn arg(value: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c);
    if !value.is_empty() && value.chars().all(plain) {
        value.to_owned()
    } else {
        quote_arg(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_arg_handles_whitespace_and_shell_metacharacters() {
        assert_eq!(quote_arg("work account; $(id)"), "'work account; $(id)'");
        assert_eq!(quote_arg("team's keychain"), "'team'\"'\"'s keychain'");
    }

    #[test]
    fn arg_quotes_only_names_a_shell_would_split_or_run() {
        assert_eq!(arg("amir3"), "amir3");
        assert_eq!(arg("amir2@sawmills.ai"), "amir2@sawmills.ai");
        assert_eq!(arg("work; touch PWNED"), "'work; touch PWNED'");
        assert_eq!(arg("my work"), "'my work'");
        assert_eq!(arg(""), "''");
    }
}
