use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::exec::{self, ExecError, ExecRequest, LiveIdentity, SelfIdentity};

/// Returns the process exit code: the child's code, or 3-7 for a refusal.
pub fn run(req: ExecRequest) -> i32 {
    match run_inner(&req) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("claudectl exec: {error}");
            error.exit_code()
        }
    }
}

fn run_inner(req: &ExecRequest) -> Result<i32, ExecError> {
    let paths = config::default_paths().map_err(|e| ExecError::Refused(format!("{e:#}")))?;
    let store = AuthStore::real(paths.clone());
    let prepared = exec::prepare(&paths, &store, req, &LiveIdentity, SelfIdentity::current()?)?;
    exec::run(&paths, prepared, req)
}
