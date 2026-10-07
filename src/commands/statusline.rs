use claudectl::config;
use claudectl::statusline;

/// Print the line, or nothing. It never fails: a prompt must not show errors.
pub fn run() {
    let Ok(paths) = config::default_paths() else {
        return;
    };
    if let Some(line) = statusline::render_within_budget(paths, chrono::Utc::now().timestamp()) {
        println!("{line}");
    }
}
