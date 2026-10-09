//! The lane lock in its own test binary. A flock belongs to the open file, and a fork by any
//! other test thread while the lock is dropped and reopened holds that file for an instant,
//! so the reopen failed at random in the shared lib test binary. This binary runs only this
//! test: no other thread forks.
use claudectl::{config::Paths, lane::Lane};

#[test]
fn a_lane_is_locked_while_open() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(tmp.path().to_path_buf());
    paths.ensure_dirs().unwrap();
    let lane = Lane::open(&paths, "lane-a").unwrap();
    assert!(Lane::open(&paths, "lane-a").is_err());
    assert!(Lane::open(&paths, "lane-b").is_ok());
    drop(lane);
    assert!(Lane::open(&paths, "lane-a").is_ok());
    assert!(Lane::open(&paths, "../x").is_err());
}
