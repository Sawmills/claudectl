# SAW-12454 plan: standalone claudectl server for Amir's Claude accounts

Scope: Amir's own Claude subscription accounts only. No sharing, no loans, no other company user.
Decision: design B (Amir, A6, 2026-10-06 16:32 PDT): "these are two different vendors, two different github projects, so connecting them together is weird."
Base: claudectl#15 head 6ad3401 (client). Server code moves from codexctl#74 (`origin/feat/provider-account-server`) into this repository.
Rule 57 challenge on codexctl plan 9ac0ea1: K3, K4, K7 and K8 and the three open-point answers stay. K1, K2 and K6 are moot, because no table or code path is shared with codexctl.

## Step 1 findings

- claudectl#15 needs no rebase. Its merge base is claudectl main 7b14c68 (2026-10-01), and main has no commit since. CI is green on 6ad3401.
- codexctl#74 holds the Claude engine: `anthropic.rs` (510 lines), `anthropic_http.rs` (224), `anthropic_login.rs` (188), `anthropic_usage.rs` (134) and six engine tests (462). The engine uses codexctl `vault` (seal, unseal, lock, digest), `store` (private directories, alias checks), `enrollment` (random bytes) and `managed::Broker` (authorize, errors).

## Shape

- A `server` Cargo feature and a `claudectl-server` binary. The client build does not change and does not pull server dependencies (axum, openidconnect, aes-gcm).
- `src/server/`:
  - `engine.rs`, `http.rs`, `login.rs`, `usage.rs`: the #74 Claude engine, with only the import paths changed.
  - `vault.rs`: AES-256-GCM seal and unseal, atomic private writes, file lock, digest.
  - `enrollment.rs`: company OIDC sign-in (Google, `hd` check) and the machine device-code flow, cut down from #74 to the parts the client uses.
  - `machines.rs`: machine registry with hashed bearer tokens, revoke, and an allow list of company users (Amir only).
  - `audit.rs`: the audit log (K8).
  - `app.rs`: routes, `/health`, `/ready`, `/metrics`, TLS requirement.
- The HTTP contract is the one claudectl#15 already calls: `/v1/enrollment/*`, `/v1/me`, `/v1/devices`, `/v1/devices/revoke`, `/v2/anthropic/{accounts,token,usage,login/*,migrations}`. One new route is `DELETE /v2/anthropic/accounts/{id}`.
- Storage mode: file store first, one replica (StatefulSet with one PVC and a process lock). HA and PostgreSQL are a follow-up ticket.

## Token, refresh, rotation, revoke

- Token issue: `POST /v2/anthropic/token {account_id, previous_revision}` returns an access token, expiry, revision and identity. It never returns a refresh token. claudectl `server run` puts the token in a private settings file for one pinned Claude process and renews it before expiry.
- Renewal handoff gate (K3): claudectl writes `settings.json` `env.CLAUDE_CODE_OAUTH_TOKEN` (central_session.rs:108) and sets an invalid process environment token (central_session.rs:124). Before any migration, a throwaway Claude session runs against a local fake API (`ANTHROPIC_BASE_URL`) across one token change. The fake records the `Authorization` header, so the result shows which value wins with no real credential. If the settings value does not win after the change, the migration stops.
- Refresh ownership (K4): the server is the only refresh owner, under one mutex per account. The server refreshes when `previous_revision` matches or when less than 5 minutes remain (not #74's 60 s). claudectl renews before that margin.
- Rotation (open point 1): refresh tokens are single use. After admission the server makes one forced refresh and an identity check, and logs a digest-only record of whether the token rotated. The phase machine (Ready, Refreshing persisted before the request, Unverified, Ready after the `/api/oauth/profile` check) stays. The server never replays a lost refresh response; the account then needs login renewal.
- Revoke (open point 2): every Claude route authorizes the machine, and the token route authorizes it again after a refresh. Machine revoke and account delete stop renewal at once. The server cannot recall an access token it already gave out, so the maximum exposure is one token lifetime. The pilot measures that lifetime and the docs record it.
- Audit (K8): one structured line per migrate, issue, refresh and revoke, with operation, machine id, account digest and result. Lines go to stderr and to an audit file sealed with the vault key. No line contains a token or a grant. Failures also count in `/metrics` with bounded labels (operation, stage, reason).
- Loans: this server has no loan route, and codexctl loans cannot reach it.

## Refresh-holder inventory and fence (before the pilot migration)

The pilot is one inactive Claude account, never the active one.

1. Inventory every holder of the pilot grant (K7), by grant digest with a tool that never prints a token:
   - claudectl profiles and `~/.claudectl/run-*` session directories on each machine;
   - the Keychain on both Macs;
   - every `~/.claude/.credentials.json` copy on the devbox;
   - the claudectl usage cache;
   - the Claude capacity guard list, headless `claude -p` jobs, cron jobs and lane panes pinned to the account.
2. Remove the pilot from the capacity guard list and confirm the removal (open point 3). The guard code refuses any alias with a server marker.
3. HQ approves the inventory. A holder of unknown status stops the migration. Backups stay a known residual risk.
4. Run `claudectl server migrate --exclusive-owner` on one machine. The claudectl fence then blocks a restore of that grant or identity there.
5. On every other holder, delete the copy by digest match and record a fence there too.

## Deploy access needed (Amir's item; the lane does not request it)

Staging only, in the same pattern as `codexctl-central`:

| # | Item | Exact need |
|---|---|---|
| 1 | ECR | Repository `claudectl-server` in account 767398060436, us-east-1, immutable tags, the `codexctl-central` lifecycle rule. |
| 2 | Image publish role | IAM role for GitHub OIDC, trust `repo:Sawmills/claudectl:ref:refs/heads/main`, ECR push to `claudectl-server` only. Repository variable `SERVER_IMAGE_PUBLISH_ROLE` in Sawmills/claudectl. |
| 3 | Secrets | SSM SecureString `/app/claudectl/vault-key` (32 random bytes, base64), `/app/claudectl/oidc-client-secret` and `/app/claudectl/metrics-token`. The shared ClusterSecretStore `aws-parameter-store` (the one codexctl uses) must be able to read `/app/claudectl/*`. |
| 4 | Company SSO | A Clerk OAuth application on `https://clerk.sawmills.ai` (as for codexctl) with redirect `https://claudectl.ue1.staging.plat.sm-svc.com/auth/callback`. Its client ID replaces the placeholder in `deploy/k8s/overlays/staging/sso.yaml`. |
| 5 | Argo CD | Application `claudectl` in project `sawmills`, source `Sawmills/claudectl` path `deploy/k8s/overlays/staging`, namespace `claudectl` (CreateNamespace). The project must allow that repository, and Argo CD needs read access to it. |
| 6 | Network | Host `claudectl.ue1.staging.plat.sm-svc.com` on the internal ALB, covered by the existing certificate, DNS and Twingate resource for `*.ue1.staging.plat.sm-svc.com`. Egress on 443 to `console.anthropic.com`, `api.anthropic.com` and Google OIDC. |
| 7 | Storage | One `encrypted-gp3-1b` PVC (1 GiB) for the file store, retained on delete. |
| 8 | Alerts | The PrometheusRule from the overlay routes warnings to #warning-alerts and pages through PagerDuty, as for codexctl. |

The PR adds the Dockerfile, the image workflow and the k8s manifests. Nothing applies until Amir grants items 1 to 6.

## Tests (test first, synthetic tokens only)

- Engine: the six #74 tests in the new module (one refresh for concurrent callers, no replay of a lost response, admission retry, successor verification, login retry, cached usage), plus the forced refresh after admission and its rotation log line.
- Margin (K4): with expiry in seconds and in milliseconds, the server refreshes inside 5 minutes and not before.
- Access: a machine without enrollment gets 401; a company user not on the allow list gets 403; a revoked machine gets no new token, also when the revoke lands during a refresh; account delete returns 410 on the next token request.
- Audit (K8): each operation writes one line, and no line contains a token. The audit file is sealed.
- Server process: `claudectl-server` starts without a Claude or Codex binary and serves `/ready`; a second process fails on the lock.
- Client: the claudectl#15 offline status and lost-receipt tests, token renewal across expiry against a test server built from the real `src/server` code, and local `use` with no network.
- K3 gate: an experiment script under `experiments/settings-renewal/` with the fake API, run once on the Mac and once on the devbox, results committed.
- Live pilot after deploy (HQ word only): one migration, a Mac and a devbox session across one renewal, revoke, and a record of rotation and token lifetime.

## Delivery

- One PR in Sawmills/claudectl, stacked on claudectl#15 (`feat/account-server`), so the client and the server review together but stay separate commits.
- Stop at `needs re-review <pr> <sha> CI green`. No merge, deploy, tag, k8s write or credential migration without HQ.
