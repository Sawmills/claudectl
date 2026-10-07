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
- Storage mode: superseded by A14. The file store stays for local tests and one-machine use; staging runs PostgreSQL with several replicas.

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

## Deploy access (superseded by the A14 section below)

The single-PVC deploy table is replaced. See "A14 revision: infra PRs".

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

## A14 revision: PostgreSQL, several replicas, Google Workspace SSO

Amir A14 to A16 (2026-10-06 17:46 to 17:49 PDT). Done so far, on the file store, at a678a29: the engine, HTTP routes, allow list, audit, delete fences, `server qualify`, and 116 tests. This section is the delta. It needs its own rule 57 challenge.

### Store

- A `Store` trait behind the engine and the registries, with two backends: `File` (today's code: tests and one-machine use) and `Postgres` (staging). One test suite runs against both; CI starts a PostgreSQL service container. The Mac runs the file suite only (no container builds on the Mac).
- Crates as in codexctl: `tokio-postgres`, `tokio-postgres-rustls`, `rustls`, `webpki-roots`, plus the RDS CA bundle as a ConfigMap. `sslmode=require`. One reconnecting client per pod, 2 s statement timeout.
- Schema (version 1), all payloads sealed with the vault key before insert; the key never enters the database:

| Table | Holds |
|---|---|
| `accounts` | `account_id` PK, `user_id`, `alias`, identity UUIDs, sealed record (grant, phase, revision, generation, admissions, `rotation_pending`), `revision` BIGINT |
| `refresh_leases` | `account_id` PK, `holder_id`, `epoch`, `expires_at` |
| `tombstones` | `account_id` PK, `user_id`, `alias`, `deleted_at`, `cleaned` |
| `pending_admissions` | digest PK, `user_id`, `alias`, sealed grant, `started_at` |
| `login_flows` | `id` PK, `user_id`, `alias`, sealed flow, `exchanging`, sealed retained response |
| `enrollment_flows` | device-code, SSO login, and approval state (today in process memory) |
| `users`, `machines` | registries with a `revision` for compare-and-swap |
| `usage_cache` | `account_id` PK, sealed usage, `next_retry_at`, poll lease |
| `audit_events` | sealed audit lines |
| `schema_migrations` | version |

### One refresh owner across replicas

- Per-account lease, as in codexctl `storage.rs:1659`. `INSERT ... ON CONFLICT DO UPDATE SET epoch = epoch + 1 WHERE expires_at <= now() OR holder_id = EXCLUDED.holder_id`. Holder = pod name + boot nonce. TTL 120 s, renewed every 30 s while held; the Anthropic exchange times out at 30 s.
- Every write that a refresh makes (Refreshing, the retained response, Unverified, Ready) is fenced: `UPDATE accounts ... WHERE revision = $expected AND EXISTS (lease row with this holder and epoch and expires_at > now() FOR UPDATE)`. A lost lease fails the write, and the request returns no token.
- A replica that finds the lease held does not refresh. It waits up to 35 s for the revision to change and returns the successor, or answers 503 `refresh_in_progress`.
- Startup takes no lease and runs no refresh; work starts per request after the lease. `/ready` checks the database and the schema version.
- Admission, delete, and login completion serialize per account with `pg_advisory_xact_lock(account_id)` in one transaction, instead of today's process mutex. The delete ordering rule (`deleted_at` against `started_at`) and the permanent tombstone stay.
- Enrollment state moves to `enrollment_flows`, so start, poll, callback, and approve can reach different replicas.
- Usage polling keeps one poller per account through a short lease on the `usage_cache` row.

### Schema owner and rollout

- `claudectl-server migrate` applies the schema. An Argo CD PreSync hook Job runs it with its own NetworkPolicy (DNS and 5432 only). `serve` never migrates and refuses a schema version it does not know.
- A Deployment with 2 replicas, zone and host anti-affinity, PDB `minAvailable: 1`, no PVC. The file-store StatefulSet is never deployed, so no file-to-database cutover is needed.

### Google Workspace OIDC (replaces Clerk)

- Issuer `https://accounts.google.com`, `allowed_domains` and `allowed_hosted_domains` = `sawmills.ai`. Port the codexctl checks: the `hd` hint on the request (`enrollment.rs:426`), `email_verified == true` (:532), and a case-insensitive `hd` claim match (:543). The `--allow-user` list (Amir only) stays on top.
- Client secret in AWS Secrets Manager `/app/claudectl/oidc-client-secret`, read by `ClusterSecretStore/aws-secrets-manager`, as for codexctl.

### Infra PRs (this lane writes them; A14 item 3)

| # | Repo | Change (copy of the codexctl B34 pattern) |
|---|---|---|
| 1 | Sawmills/infra | `stacks/catalog/ecr.yaml`: repository `claudectl-server` |
| 2 | Sawmills/infra | `stacks/catalog/github-oidc-role/claudectl.yaml` (`gha-claudectl`, `repo:Sawmills/claudectl:ref:refs/heads/main`, ECR push to `claudectl-server` only) and its import in `core/artifacts/global-region/baseline.yaml` |
| 3 | Sawmills/infra | `components/terraform/rds/claudectl` and `stacks/catalog/rds/claudectl.yaml` on the STAGING quota-manager instance: database `claudectl`, a login role (no superuser, createdb, createrole, inherit; connection limit 30), `REVOKE CONNECT, TEMPORARY ON DATABASE claudectl FROM PUBLIC`, SSM `/rds/quota-manager/claudectl/*` |
| 4 | Sawmills/infra | `manifests/claudectl/external-secret.yaml` (`claudectl-postgres`) as `eks/claudectl-db-secret` |
| 5 | Sawmills/argocd-deploy | `plat/ue1-staging/argocd/claudectl-application.yaml` (path `deploy/k8s/overlays/staging`) |
| 6 | Sawmills/claudectl | overlay: Deployment, PDB, PreSync migration Job and its NetworkPolicy, RDS CA ConfigMap, ExternalSecrets, ingress `claudectl.ue1.staging.plat.sm-svc.com`, egress 443 and 5432, alerts |

The shared ExternalSecrets IAM grant already covers `app/*` and `rds/*`, so no store change is needed (`eks.yaml:75-79`).

### Steps that need Amir or HQ

- **Google OAuth client (A15).** The lane creates it with computer use in Dia, as an internal app with redirect `https://claudectl.ue1.staging.plat.sm-svc.com/auth/callback`. Amir is needed if Google asks for MFA, an admin role, or a consent-screen change. This session has the computer-use skill but no computer-use tool loaded yet; if none loads, the lane stops and tells HQ.
- **RDS apply (A16).** CI apply excludes the `rds/*` components; they apply through the in-cluster (private VPC) Atmos path. The lane runs it only if that path works from this session; otherwise Amir runs `atmos terraform apply rds/claudectl -s <staging stack>`. If only the prod quota-manager instance fits, the lane stops. The agent found the codexctl database on the staging instance, so staging fits.
- **Hand-set secrets.** `/app/claudectl/vault-key` and `/app/claudectl/metrics-token` (SSM), generated from stdin and never printed. Lane with HQ approval; Amir if the lane's AWS role cannot write them.
- **k8s writes and the Argo registration.** The `eks/claudectl-db-secret` apply and the argocd-deploy merge (automated sync = deploy) wait for HQ.

### Tests added for HA

- The engine and HTTP suites run on both backends.
- Two engines (two holders) on one database: concurrent token requests on both refresh once; a follower returns the successor; a lease lost during a refresh fences the write and returns no token; a holder killed while Refreshing is never replayed by the other.
- Enrollment start on one replica, poll and approve on the other.
- A delete on one replica during a renewal on the other is refused by the ordering rule.
- `serve` refuses an unknown schema version; `migrate` is idempotent.
- Google `hd` and `email_verified` checks.
