# Account-server preview validation

2026-10-03. Implementation branches are separate from the research PR. All
synthetic fixtures use fake grants and prohibit external inference requests.

| Check                                                                                                      | Result                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Client format and Clippy                                                                                   | Passed                                                                                                                            |
| Client `cargo test --all-targets` on Linux ARM64                                                           | 189 passed                                                                                                                        |
| Server format and Clippy                                                                                   | Passed                                                                                                                            |
| Server `cargo test --all-targets --locked --features central-prototype` in an isolated Rust 1.89 container | 832 passed, 1 pre-existing ignored                                                                                                |
| Client/server locked Linux release builds                                                                  | Passed                                                                                                                            |
| Mac ARM64 client release build and targeted client/session tests                                           | Passed; migration CLI integration is Linux-only to avoid real Keychain reads in tests                                             |
| Standalone Claude-only container                                                                           | Built; help, initialization, `/health` and `/ready` passed without Codex                                                          |
| Linux 2.1.280 settings lifecycle                                                                           | Seven cases passed                                                                                                                |
| Mac 2.1.288 settings lifecycle with conflicting synthetic Keychain                                         | Eight cases passed                                                                                                                |
| Full launcher renews during an eight-second Bash operation, Linux and Mac                                  | A request → one tool operation → B request; tool ran once; private session credentials removed                                    |
| Abrupt wrapper exit                                                                                        | Next launch retires an expired abandoned directory while keeping a live session's directory                                       |
| Overlapping local/server launches in one process                                                           | Shared signal ownership guard refuses the second launch before starting a child                                                   |
| Lost migration reply                                                                                       | Local reads/writes and duplicate aliases stay fenced; receipt retry retires the retained client grant                             |
| Provider refresh/admission/login recovery                                                                  | Failed verification retries retained successors/candidates/responses without repeating the refresh or authorization-code exchange |

Evidence is in
[`experiments/settings-renewal`](../experiments/settings-renewal), including the
executed harnesses and reduced non-secret result files. Debug builds hash the
vendor executable slowly; the full-launcher experiment uses release builds and a
startup allowance separate from the eight-second tool operation. On Mac the
experiment permits writes to the unique fixture's normal Claude tool-temp path,
while retaining external-network and real-Keychain denies.

The shared-host server rerun encountered the existing fail-closed open-file check:
`lsof` cannot stat another task's Docker namespace/overlay mounts. No production
safety check or other task's container was changed. The complete suite passed in
an isolated container as an unprivileged user with the package's minimum Rust
version. This distinguishes a clean run from the shared-host failure.

## Live check boundaries

An authorized, limited check reads a selected inactive profile's existing access
token on the Mac, verifies its account/organization through `/api/oauth/profile`,
and feeds only that access token to the client through a temporary loopback broker.
It does not enroll a production machine, move refresh ownership, exchange a refresh
token, or establish SSO deployment readiness. Temporary credentials are private
and deleted afterward. Account identifiers and tokens are omitted from committed
reports.

The first selected profile had Team plan metadata and passed identity verification;
Claude reported its weekly limit was exhausted. A second inactive Team profile had
available quota. The client then returned exit 0, `is_error=false`, and a visible
nine-character reply with eight output tokens. The exact eight-character marker
check did not match; the recorded acceptance is successful inference, not exact
model formatting. See the [non-identifying live report](../experiments/settings-renewal/live-access-result.json).
No refresh grant was transferred or exchanged, no client refresh fields remained,
and the temporary home was deleted. This does not establish invoice/billing
behavior, real rotation, or production SSO. Full migration remains pending: SSH still receives macOS
error 36 when reading the authoritative live Keychain entry, despite a successful
native unlock. Other grant holders have not been conclusively inventoried.

Release gates remain native Mac Keychain acceptance, managed-policy lifetime
behavior, SSO staging deployment, full ownership transfer, actual access expiry and
repeated rotation on both clients, and subscription entitlement/billing evidence.
The implementation is a draft for review, not a release claim.
