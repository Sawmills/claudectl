/// Quote one argument for safe copy-paste into a POSIX shell.
pub fn quote_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_arg_handles_whitespace_and_shell_metacharacters() {
        assert_eq!(quote_arg("work account; $(id)"), "'work account; $(id)'");
        assert_eq!(quote_arg("team's keychain"), "'team'\"'\"'s keychain'");
    }
}
