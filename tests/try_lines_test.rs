//! Every user-facing refusal that the UX review listed ends with the next command to run
//! (SAW-12677). The test reads the source, so a new wording cannot drop the `Try:` line.
fn call_containing(source: &str, needle: &str) -> String {
    let at = source
        .find(needle)
        .unwrap_or_else(|| panic!("message gone: {needle}"));
    // The enclosing macro or call: from the last `bail!(`/`context(`/`.into()` start back
    // to the closing `)` that ends it. A window of the text around the needle is enough.
    let start = source[..at]
        .rfind("bail!(")
        .into_iter()
        .chain(source[..at].rfind("context("))
        .max()
        .unwrap_or(at);
    let end = source[at..].find(");").map_or(source.len(), |e| at + e);
    source[start..end].to_owned()
}

#[test]
fn listed_refusals_end_with_a_try_line() {
    for (file, needle) in [
        (
            "src/central_session.rs",
            "inherited credential or routing override",
        ),
        (
            "src/central_session.rs",
            "launch argument overrides account isolation",
        ),
        ("src/central_session.rs", "Claude executable not found"),
        ("src/central.rs", "invalid Claude login challenge"),
        (
            "src/commands/use_profile.rs",
            "no saved profile has fresh usage below the general limits",
        ),
        ("src/accounts.rs", "no account named"),
        (
            "src/central.rs",
            "this machine is not connected to an account server",
        ),
    ] {
        let source = std::fs::read_to_string(file).unwrap();
        let call = call_containing(&source, needle);
        assert!(
            call.contains("Try: "),
            "{file}: '{needle}' has no Try: line:\n{call}"
        );
    }
}

#[test]
fn the_limit_step_names_a_command() {
    let source = std::fs::read_to_string("src/commands/status.rs").unwrap();
    assert!(
        !source.contains("\"Use another model or account\""),
        "a step without a command"
    );
}
