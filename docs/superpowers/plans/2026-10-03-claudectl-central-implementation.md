# Account-server implementation plan

2026-10-03. Work sequence approved by the subsequent “do it all” instruction.
Implementation is under review separately from the research PR. See
[the preview runbook](../../account-server.md) for implemented commands, executed
checks, and remaining pilot gates. Real-account pilot handling is authorized, but
no grant has been migrated while ownership remains unresolved.

## Outcome and current evidence

A Claude-only installation has one standalone account server, company SSO, and
claudectl on each machine. It requires neither Codex nor an OpenAI account. The
server owns refresh credentials; each client receives only access credentials.
Sawmills can enable both providers in its existing deployment.

Synthetic Linux 2.1.280 and macOS 2.1.288 experiments demonstrated credential-file
reload, simulated 401 recovery, and interactive session continuity. The
[Mac Keychain follow-up](../specs/2026-10-03-claudectl-macos-keychain-experiment.md)
found that a matching Keychain credential overrides the file, including when it
appears after launch. A private config selects a different Keychain service in the
tested build, but an empty `CLAUDE_SECURESTORAGE_CONFIG_DIR` redirects lookup to
the ordinary service. Neither a random directory nor a one-time absence check is
sufficient to guarantee continuous source isolation.

The immediate next work is to settle that isolation boundary. Shared server work
can proceed independently, but macOS continuous sessions must remain unavailable
until the first milestone passes. Do not ship the test's fake `security` command
as an authentication mechanism.

## 1. Establish the macOS launch boundary

**Deliverable:** a version-pinned launcher contract and executable compatibility
checks for both Linux and macOS, before connecting a real server account.

- Start from `src/exec.rs` environment/settings checks and private-config handling.
  Keep existing descriptor-based local exec behavior unchanged. Add a separate
  server-account path; do not introduce client refresh to local exec.
- Reject credential/routing overrides from inherited environment and all applicable
  settings. Include `CLAUDE_SECURESTORAGE_CONFIG_DIR`, `CLAUDE_CONFIG_DIR`, helpers,
  environment/descriptor tokens, and provider selectors. The existing
  `CLAUDE_CODE_*`/`ANTHROPIC_*` name rules do not cover the newly observed setting.
  Account for empty values; diagnostics name settings without printing values.
- Allocate a new private config for each launch. Pin server-account identity and
  token revision separately from disposable credentials and resumable conversation
  state. Never reuse another account's config or its `oauthAccount` metadata.
- Evaluate a narrowly scoped OS restriction that denies Claude's Keychain credential
  access throughout the process lifetime. The research sandbox demonstrates file
  reload with Keychain blocked; it is not yet a production sandbox profile. macOS
  sandbox restrictions are inherited by tool children, so check Git credential
  helpers, SSH, signing, and other tools that legitimately need Keychain access.
  Test normal network and workspace access separately from credential restrictions.
- If that boundary cannot preserve required tool behavior, revise the macOS
  transport design before enabling continuous sessions. A bounded environment/FD
  launch with explicit restart/resume is a known fallback, with different behavior;
  it must not be represented as uninterrupted renewal.

**Acceptance:** with synthetic global, matching, and late-appearing Keychain
credentials, the selected file supplies A then B, or launch/continuation is refused
before any request uses the conflicting credential. Missing or malformed files
must not select Keychain credentials. Inherited and settings-based storage overrides
must be refused. Repeat streaming and terminal reload tests under the chosen
boundary and verify representative tool execution. Unsupported versions fail
clearly instead of silently weakening isolation. The current command-stub test
establishes source precedence, not native Keychain ACL behavior or this boundary.

## 2. Extract and package the shared account server

**Deliverable:** a neutral standalone server package in the codexctl repository,
with explicit provider enablement and unchanged existing OpenAI client behavior.
A separate repository is unnecessary initially; settle the package name at release.

Start from `src/central/{managed,enrollment,transport,vault,server}.rs` in the
[reviewed codexctl source](https://github.com/Sawmills/codexctl/tree/6a290c9bc23f53e5dfcccefa7c8d6e6e21a8631e/src/central).
Separate SSO, machine authorization, encrypted persistence, ownership locks, and
HTTP lifecycle from OpenAI auth parsing, billing, and Codex App Server startup.

Add a versioned provider-aware protocol and vault schema. Key reservations by
provider and verified identity; aliases by company user, provider, and alias.
Token responses contain access token, verified account identity, expiry, scopes,
and an opaque revision. They never expose refresh credentials. Retain OpenAI-only
v1 endpoints and reject unknown providers. Existing machine credentials acquire
no new provider access without an explicit enrollment/upgrade decision.

**Acceptance:** Claude-only startup, readiness, enrollment, and fake-provider
acquisition work with no Codex binary or OpenAI account/configuration present.
OpenAI-only v1 clients retain their behavior. Cross-user/provider/account access,
disabled users, and revoked machines are denied. Exercise stopped-writer schema
upgrade/restore with existing encrypted records; reject ambiguous or downgrade
reads. Account for the extraction and packaging work explicitly in this change.

## 3. Implement the Claude refresh owner

**Deliverable:** one server-side Claude adapter and durable refresh owner, using
the existing `src/oauth.rs` and `src/api.rs` request semantics as a reference.

Keep identity verification, grant exchange, refresh-result classification, and
usage parsing inside the adapter. Keep locking, journal persistence, company-user
authorization, and delivery in the shared server. All refresh consumers, including
usage and login renewal, go through the same owner. Persist a successor grant
before delivering its access token. Use actual expiry and revision metadata.

Treat a refresh timeout after possible provider rotation as uncertain ownership.
Quarantine it for reconciliation or login renewal; never retry an old backup
automatically. Preserve an acquired grant if subsequent verification or activation
fails. A second company user cannot reserve the same provider identity.

**Acceptance:** a synthetic provider proves concurrent acquisitions and repeated
rejection of one revision cause at most one exchange, old revisions receive the
successor, and restart reads durable state. Inject failures before exchange, after
provider rotation, before vault persistence, and before response delivery. Verify
no refresh material appears in responses, logs, metrics, receipts, or client files.
Do not classify every 403/429 as a reason to refresh.

## 4. Add machine enrollment and continuous client sessions

**Deliverable:** a separate claudectl server-account command path with headless
SSO enrollment, account discovery, launch, revocation handling, and disconnect.

Use the shared server protocol, not the Codex native provider format. Bind every
acquisition to the authenticated company user, machine, provider, and selected
server account. Keep local profile layout, active marker, switching, and active
refresh exclusions unchanged.

After milestone 1, add a local credential writer that obtains access-only grants
and atomically replaces a mode-0600 credential file in a mode-0700 directory.
Check identity, expiry, and monotonic revision before publication; serialize
publishers and reject symlinks or unsafe paths. Use a supervised writer whose
lifetime follows the child; clean up on exit and handle stale state after crashes.
Schedule renewal before server-reported expiry with skew margin and bounded retry.

On account-server outage, retain a still-usable token and report the outage. If
it expires or is rejected, preserve conversation state and allow explicit prompt
retry after recovery. Never fall back to local refresh or replay tool actions.
Revoking a machine stops new acquisition; an already delivered token can remain
usable until provider expiry/rejection. Resume into a new credential namespace
while retaining the selected server-account identity.

**Acceptance:** concurrent synthetic Linux/Mac clients cross multiple renewals,
including during a long tool operation, without restarting or changing accounts.
Test writer crash, partial response/write, account mismatch, old revision, clock
skew, outage/recovery, child exit, restart/resume, and machine revocation. Exercise
settings/policy refusal and the Keychain conflict matrix from milestone 1. Inspect
only synthetic client state to prove it contains no refresh grants.

## 5. Add usage and optional status-line integration

**Deliverable:** authorized server-cached subscription usage and a local cache
reader for the session's pinned account.

Reuse the design's five-minute cache, reset-aware expiry, shared polling spacing,
and 429 cooldown policy. Preserve null/unknown and model-specific fields. Native
Pro/Max rate-limit fields supplement the cache; do not promise Team availability.
Status-line redraws read local data only, never acquire credentials or poll
Anthropic. Preserve an existing user status line unless explicitly selected.

**Acceptance:** simultaneous machines do not multiply provider polling; cached
status performs no network or refresh; 429/Retry-After and stale/offline/unknown
states display accurately; identity changes never reuse another account's cache.

## 6. Implement resumable migration

**Deliverable:** an explicit cutover separate from local switching, following the
design's inventory → fence → import/verify → receipt → retirement sequence.

Require an inventory of every prior grant holder and an exclusive-owner declaration.
Stop old sessions and binaries before remote refresh is possible. Capture outgoing
rotated live tokens only with matching identity. Run the existing macOS Keychain
unlock preflight before live mutation; never handle a Keychain password. Include
custom credential namespaces, duplicate aliases, and external backup copies.

Journal intent locally, reserve provider identity globally, import idempotently,
and reconcile timeouts with the server receipt. Leave uncertain migrations fenced.
After durable server ownership, retire usable client refresh copies and preserve
non-secret account references. Activation failure preserves the saved server grant.
Do not implement implicit reverse migration or restore a copied refresh owner.

**Acceptance:** inject faults at every durable boundary, including Keychain locked,
unreachable old machine, duplicate identity, stale alias, lost response, and failed
activation. Repeated migration resumes safely. Existing local `use` remains
network-free; active local profiles and aliases sharing their grant never refresh.

## 7. Run a dedicated live pilot, then release

The original research brief explicitly says “never log in a real account.” This
plan does not authorize an exception. Before a live pilot, Amir must identify an
account reserved for the test and explicitly authorize real login/token handling.
Do not select an active local profile implicitly. Provider permission is not an
additional prerequisite; that risk was already accepted.

Use one staging account server, the Linux machine, and the Mac mini. Begin only
after synthetic ownership and launch-isolation acceptance pass. Establish refresh
ownership directly on the server, with no grant copies in client profiles.

1. Verify identity and subscription billing on both machines with minimal prompts.
2. Cross actual access expiry and repeated server rotation in one running session
   on each machine. Record only non-secret revisions, times, outcomes, and account
   references; never print credentials or raw authentication responses.
3. Test server outage/restart and restoration of the same sessions, machine
   revocation, usage cooldowns, and native/cache status-line behavior. Test tool
   continuity without replaying completed effects.
4. Verify the Mac namespace cannot select a conflicting login and that both clients
   hold access-only state. Test actual Keychain behavior in a controlled synthetic
   OS fixture, without reading unrelated saved credentials.
5. Exercise migration and activation failure with the admitted test account, then
   clean up test machines and access files. Recovery keeps one server refresh owner;
   it never sends an old refresh grant back to a client.

Release only the OS/version/plan combinations that pass. One test subscription
does not establish every Pro/Max/Team combination. Start with one server replica,
document encrypted backup and uncertain-refresh recovery, and validate restore
without simultaneously starting a second owner.

## Review and validation per change

Keep these milestones as separately reviewable PRs across the server and client
repositories. Ship server protocol compatibility before clients consume it; finish
the macOS isolation milestone before enabling that client's continuous sessions.
Run each repository's documented format, lint, and test checks for implementation
changes, including `cargo fmt --all -- --check`, `cargo clippy --all-targets`, and
`cargo test --all-targets` here. Build release targets on supported platforms and
run the pinned Claude compatibility harness when upgrading the vendor binary.

For this documentation PR, validate Markdown formatting, relative links, Python
harness syntax, equality with the executed harness, recorded synthetic outcomes,
and `git diff --check`. Product tests do not establish these external-client facts.
