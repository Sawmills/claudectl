use super::*;
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

struct Server {
    address: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let count = requests.clone();
        let stopped = stop.clone();
        let responses = Mutex::new(VecDeque::from(responses));
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let response = responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| response(500, "", "{}"));
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn response(status: u16, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    )
}

struct Harness {
    root: tempfile::TempDir,
    server: Server,
}

impl Harness {
    fn new(responses: Vec<String>) -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            server: Server::new(responses),
        }
    }

    async fn query(&self, token: &str, mode: FetchMode, now: i64) -> Snapshot {
        let mut cache = UsageCache::open(self.root.path()).unwrap();
        cache.endpoint = format!("http://{}", self.server.address);
        cache.request_spacing = Duration::ZERO;
        cache
            .get(&reqwest::Client::new(), token, mode, now)
            .await
            .unwrap()
    }

    fn count(&self) -> usize {
        self.server.requests.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn when_reopened_with_recent_data_then_no_second_request() {
    let h = Harness::new(vec![response(200, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Normal, 1001).await;

    assert_eq!(h.count(), 1);
    assert_eq!(result.source, "cached");
    assert!(result.fresh);
}

#[tokio::test]
async fn when_cooldown_is_saved_then_refresh_and_other_accounts_send_no_requests() {
    let h = Harness::new(vec![response(429, "Retry-After: 900\r\n", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-b", FetchMode::Refresh, 1001).await;

    assert_eq!(h.count(), 1);
    assert_eq!(result.next_fetch_at, Some(1900));
    assert_eq!(result.source, "cooldown");
}

#[tokio::test]
async fn when_retry_after_is_zero_then_local_backoff_still_applies() {
    let h = Harness::new(vec![response(429, "Retry-After: 0\r\n", "{}")]);

    let result = h.query("test-only-a", FetchMode::Normal, 1000).await;

    assert_eq!(result.next_fetch_at, Some(1300));
}

#[tokio::test]
async fn when_repeated_429_has_no_retry_header_then_backoff_increases() {
    let h = Harness::new(vec![response(429, "", "{}"), response(429, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Normal, 1300).await;

    assert_eq!(h.count(), 2);
    assert_eq!(result.next_fetch_at, Some(1900));
}

#[tokio::test]
async fn when_cooldown_expires_then_one_success_restores_live_data() {
    let h = Harness::new(vec![response(429, "", "{}"), response(200, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Normal, 1300).await;

    assert_eq!(h.count(), 2);
    assert_eq!(result.source, "live");
    assert!(result.error.is_none());
}

#[tokio::test]
async fn when_refresh_fails_then_last_usage_and_age_are_preserved() {
    let h = Harness::new(vec![
        response(200, "", r#"{"seven_day":{"utilization":71}}"#),
        response(503, "", "{}"),
    ]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Normal, 1300).await;

    assert_eq!(
        result.usage.unwrap().seven_day.unwrap().utilization,
        Some(71.0)
    );
    assert_eq!(result.fetched_at, Some(1000));
    assert_eq!(
        result.error.as_deref(),
        Some("usage fetch failed (HTTP 503)")
    );
}

#[tokio::test]
async fn when_cached_only_then_no_network_even_without_data() {
    let h = Harness::new(vec![]);

    let result = h.query("test-only-a", FetchMode::Cached, 1000).await;

    assert_eq!(h.count(), 0);
    assert!(result.usage.is_none());
}

#[tokio::test]
async fn when_token_changes_then_cached_identity_is_not_reused() {
    let h = Harness::new(vec![response(200, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-b", FetchMode::Cached, 1001).await;

    assert!(result.usage.is_none());
}

#[tokio::test]
async fn when_window_resets_then_recent_cache_is_refetched() {
    let h = Harness::new(vec![
        response(
            200,
            "",
            r#"{"five_hour":{"utilization":100,"resets_at":"1970-01-01T00:18:20Z"}}"#,
        ),
        response(200, "", "{}"),
    ]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Normal, 1100).await;

    assert_eq!(h.count(), 2);
    assert_eq!(result.source, "live");
}

#[tokio::test]
async fn when_refresh_is_requested_then_recent_success_can_be_refetched() {
    let h = Harness::new(vec![response(200, "", "{}"), response(200, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Refresh, 1001).await;

    assert_eq!(h.count(), 2);
    assert_eq!(result.fetched_at, Some(1001));
}

#[tokio::test]
async fn when_saved_then_cache_contains_no_token_or_response_error_body() {
    let h = Harness::new(vec![response(429, "", "sensitive response body")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let file = std::fs::read_to_string(h.root.path().join("usage/cache-v1.json")).unwrap();

    assert!(!file.contains("test-only-a"));
    assert!(!file.contains("sensitive response body"));
}

#[test]
fn when_cache_is_corrupt_then_fail_before_network() {
    let h = Harness::new(vec![]);
    std::fs::create_dir(h.root.path().join("usage")).unwrap();
    std::fs::write(h.root.path().join("usage/cache-v1.json"), "invalid").unwrap();

    assert!(UsageCache::open(h.root.path()).is_err());
    assert_eq!(h.count(), 0);
}

#[test]
fn when_another_check_holds_lock_then_no_second_owner() {
    let root = tempfile::tempdir().unwrap();
    let _first = UsageCache::open(root.path()).unwrap();

    assert!(UsageCache::open(root.path()).is_err());
}

#[tokio::test]
async fn when_recent_fetch_fails_then_refresh_cannot_bypass_error_backoff() {
    let h = Harness::new(vec![response(503, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let result = h.query("test-only-a", FetchMode::Refresh, 1001).await;

    assert_eq!(h.count(), 1);
    assert_eq!(result.next_fetch_at, Some(1300));
}

#[test]
fn when_token_refresh_transport_fails_then_next_command_can_retry() {
    let root = tempfile::tempdir().unwrap();
    let mut cache = UsageCache::open(root.path()).unwrap();
    cache
        .refresh_failed("test-only-a", &anyhow::anyhow!("test error"), 1000)
        .unwrap();
    drop(cache);

    let cache = UsageCache::open(root.path()).unwrap();

    assert!(cache.should_request("test-only-a", FetchMode::Refresh, 1001));
}

#[cfg(unix)]
#[tokio::test]
async fn when_cache_is_written_then_only_owner_can_read_it() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(vec![response(200, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;

    let permissions = std::fs::metadata(h.root.path().join("usage/cache-v1.json"))
        .unwrap()
        .permissions();

    assert_eq!(permissions.mode() & 0o777, 0o600);
}

#[tokio::test]
async fn when_429_is_received_then_distinguish_failed_request_from_skipped_request() {
    let h = Harness::new(vec![response(429, "", "{}")]);

    let rejected = h.query("test-only-a", FetchMode::Normal, 1000).await;
    let skipped = h.query("test-only-a", FetchMode::Normal, 1001).await;

    assert_eq!(rejected.source, "failed");
    assert_eq!(skipped.source, "cooldown");
    assert_eq!(h.count(), 1);
}

#[tokio::test]
async fn when_aliases_share_token_then_refresh_fetches_once_per_command() {
    let h = Harness::new(vec![response(200, "", "{}")]);
    let mut cache = UsageCache::open(h.root.path()).unwrap();
    cache.endpoint = format!("http://{}", h.server.address);
    cache.request_spacing = Duration::ZERO;
    let client = reqwest::Client::new();

    cache
        .get(&client, "test-only-a", FetchMode::Refresh, 1000)
        .await
        .unwrap();
    cache
        .get(&client, "test-only-a", FetchMode::Refresh, 1001)
        .await
        .unwrap();

    assert_eq!(h.count(), 1);
}

#[tokio::test]
async fn when_another_account_is_limited_then_fresh_success_remains_usable() {
    let h = Harness::new(vec![response(200, "", "{}"), response(429, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;
    h.query("test-only-b", FetchMode::Normal, 1001).await;

    let result = h.query("test-only-a", FetchMode::Normal, 1002).await;

    assert!(result.error.is_none());
    assert!(result.fresh);
    assert_eq!(h.count(), 2);
}

#[tokio::test]
async fn when_token_endpoint_is_limited_then_other_accounts_remain_eligible() {
    let h = Harness::new(vec![response(429, "Retry-After: 900\r\n", "{}")]);
    let error = api::fetch_usage_at(
        &reqwest::Client::new(),
        "test-only-a",
        &format!("http://{}", h.server.address),
    )
    .await
    .err()
    .unwrap();
    let mut cache = UsageCache::open(h.root.path()).unwrap();

    let result = cache.refresh_failed("test-only-a", &error, 1000).unwrap();

    assert!(cache.should_request("test-only-b", FetchMode::Normal, 1001));
    assert!(!cache.should_request("test-only-a", FetchMode::Refresh, 1001));
    assert_eq!(result.next_fetch_at, Some(1900));
    cache.refresh_failed("test-only-a", &error, 1001).unwrap();
    assert_eq!(
        cache.state.entries[&UsageCache::key("test-only-a")].failures,
        1
    );
    cache.refresh_failed("test-only-b", &error, 1001).unwrap();
    drop(cache);
    let reopened = UsageCache::open(h.root.path()).unwrap();
    assert!(!reopened.should_request("test-only-a", FetchMode::Refresh, 1002));
    assert!(!reopened.should_request("test-only-b", FetchMode::Refresh, 1002));
}

#[tokio::test]
async fn when_old_tokens_are_unused_for_a_day_then_prune_their_entries() {
    let h = Harness::new(vec![response(200, "", "{}"), response(200, "", "{}")]);
    h.query("test-only-a", FetchMode::Normal, 1000).await;
    h.query("test-only-b", FetchMode::Normal, 87401).await;

    let result = h.query("test-only-a", FetchMode::Cached, 87402).await;

    assert!(result.usage.is_none());
}

#[tokio::test]
async fn refresh_cooldown_survives_reopen_for_a_different_access_token() {
    let root = tempfile::tempdir().unwrap();
    let h = Harness::new(vec![response(429, "Retry-After: 600\r\n", "{}")]);
    let error = api::fetch_usage_at(
        &reqwest::Client::new(),
        "test-access",
        &format!("http://{}", h.server.address),
    )
    .await
    .err()
    .unwrap();
    let mut cache = UsageCache::open(root.path()).unwrap();
    cache
        .refresh_failed_for_grant("access-one", "shared-grant", &error, 1000)
        .unwrap();
    drop(cache);
    let cache = UsageCache::open(root.path()).unwrap();
    let blocked = cache
        .refresh_cooldown("access-two", "shared-grant", 1001)
        .unwrap();
    assert_eq!(blocked.next_fetch_at, Some(1600));
    assert!(blocked.error.unwrap().contains("429"));
    assert!(
        cache
            .refresh_cooldown("access-two", "other-grant", 1001)
            .is_none()
    );
    assert!(
        cache
            .refresh_cooldown("access-two", "shared-grant", 1600)
            .is_none()
    );
}

#[tokio::test]
async fn failed_alias_reports_the_full_shared_grant_delay() {
    let h = Harness::new(vec![response(503, "", "{}")]);
    let error = api::fetch_usage_at(
        &reqwest::Client::new(),
        "test-access",
        &format!("http://{}", h.server.address),
    )
    .await
    .err()
    .unwrap();
    let mut cache = UsageCache::open(h.root.path()).unwrap();
    cache
        .refresh_failed_for_grant("access-one", "shared-grant", &error, 1000)
        .unwrap();
    drop(cache);
    let mut cache = UsageCache::open(h.root.path()).unwrap();
    let failed = cache
        .refresh_failed_for_grant("access-two", "shared-grant", &error, 1300)
        .unwrap();
    assert_eq!(failed.next_fetch_at, Some(1900));
}

#[tokio::test]
async fn recovered_grant_starts_a_new_failure_backoff() {
    let h = Harness::new(vec![response(503, "", "{}")]);
    let error = api::fetch_usage_at(
        &reqwest::Client::new(),
        "test-access",
        &format!("http://{}", h.server.address),
    )
    .await
    .err()
    .unwrap();
    let mut cache = UsageCache::open(h.root.path()).unwrap();
    cache
        .refresh_failed_for_grant("access-one", "shared-grant", &error, 1000)
        .unwrap();
    cache.refresh_succeeded("shared-grant").unwrap();
    drop(cache);
    let mut cache = UsageCache::open(h.root.path()).unwrap();
    let failed = cache
        .refresh_failed_for_grant("access-two", "shared-grant", &error, 2000)
        .unwrap();
    assert_eq!(failed.next_fetch_at, Some(2300));
}
