# claudectl account server: staging runbook

Scope: Amir's own Claude subscription accounts only (SAW-12454). No other company user is
on the allow list, and no account is shared or loaned.

Reference: [account-server.md](account-server.md) describes the commands and the design;
[the plan](superpowers/plans/2026-10-06-saw-12454-claude-server.md) records the decisions.

## Components

| Part                            | Where                                                                                                                             |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Server image `claudectl-server` | ECR `767398060436.dkr.ecr.us-east-1.amazonaws.com/claudectl-server`, built by `.github/workflows/server-image.yml` on `main`      |
| Kubernetes manifests            | `deploy/k8s` (base + `overlays/staging`), namespace `claudectl`                                                                   |
| Argo CD application             | Sawmills/argocd-deploy `plat/ue1-staging/argocd/claudectl-application.yaml`                                                       |
| Database `claudectl`            | staging quota-manager RDS, Sawmills/infra component `rds/claudectl`                                                               |
| Database secrets                | `claudectl-postgres` (runtime), `claudectl-migrator-postgres` (schema owner), infra `eks/claudectl-db-secret`                     |
| App secrets                     | SSM `/app/claudectl/vault-key`, `/app/claudectl/metrics-token`, `/app/claudectl/oidc-client-secret`                               |
| Sign-in                         | Google Workspace OAuth client (Internal, Web application), redirect `https://claudectl.ue1.staging.plat.sm-svc.com/auth/callback` |
| Endpoint                        | `https://claudectl.ue1.staging.plat.sm-svc.com` (internal ALB, Twingate)                                                          |

## First deploy, in order

Each step needs the one before it. Stop at the first failure.

1. **Database.** Merge Sawmills/infra `rds/claudectl`. From the staging operator Pod (see
   the infra component README), run:

   ```shell
   atmos terraform plan rds/claudectl -s plat-ue1-staging
   atmos terraform deploy rds/claudectl -s plat-ue1-staging
   atmos terraform deploy eks/claudectl-db-secret -s plat-ue1-staging
   ```

   Check: `kubectl -n claudectl get secret claudectl-postgres claudectl-migrator-postgres`.

2. **App secrets.** Create them from stdin; never put a value on a command line:

   ```shell
   openssl rand -base64 32 | tr -d '\n' | aws ssm put-parameter --name /app/claudectl/vault-key \
     --type SecureString --value file:///dev/stdin
   openssl rand -hex 32 | tr -d '\n' | aws ssm put-parameter --name /app/claudectl/metrics-token \
     --type SecureString --value file:///dev/stdin
   ```

   The OAuth client secret goes to SSM `/app/claudectl/oidc-client-secret` (SecureString), the
   same way; staging has no Secrets Manager store. A lost vault key loses every grant; there is no recovery without it.

3. **Image.** Merge Sawmills/claudectl. The Server image workflow prints
   `Deploy after review: <image>@sha256:...`. Pin that digest in
   `deploy/k8s/overlays/staging/kustomization.yaml` (`images[0].digest`), and put the Google
   client ID into `overlays/staging/sso.yaml`. Merge that change.

4. **Argo CD.** Merge the argocd-deploy application. The sync runs the PreSync migration Job
   first, then two server replicas. Check:

   ```shell
   kubectl -n claudectl get job claudectl-migrate        # Complete
   kubectl -n claudectl get pods -l app.kubernetes.io/component=server   # 2/2 Running, Ready
   curl -sf https://claudectl.ue1.staging.plat.sm-svc.com/ready
   ```

5. **Enroll a machine.** On the Mac:

   ```shell
   claudectl server connect https://claudectl.ue1.staging.plat.sm-svc.com --name mac
   claudectl server devices
   ```

   Sign in with the company Google account. The approval page must show the same code as the
   terminal.

## Pilot migration (one inactive account, never the active one)

The migration moves the refresh grant to the server. It is one-way: never restore an old
copy afterwards.

1. **Qualify the Claude build** on every machine that will run sessions:
   `claudectl server qualify --claude claude`. The command resolves the name on `PATH` and
   follows symlinks to the real build. A build that does not pass is refused by `server run`.
   `server run` also checks a new build on first use (for example after a Claude Code
   update); a failed build is refused for one hour, then `server qualify` checks it again.
2. **Inventory every holder** of the pilot grant: claudectl profiles and `~/.claudectl/run-*`
   directories on each machine, the Keychain on both Macs, every `~/.claude/.credentials.json`
   copy on the devbox, the claudectl usage cache, the Claude capacity guard list, headless
   `claude -p` jobs, cron jobs, and lane panes pinned to the account. Record the result; a
   holder of unknown status stops the migration.
3. **Remove the pilot** from the capacity guard list and confirm it.
4. **HQ approves** the inventory.
5. **Migrate** on one machine: `claudectl server migrate <alias> --exclusive-owner`. The server
   refreshes once and completes only if the provider returns a new refresh token. If it
   answers `refresh_token_not_rotated`, the old copies stay valid: stop and report.
   The same holds for `migration_superseded`: a login renewal replaced the grant before it
   rotated.
6. **Retire the other copies** by digest match on every other holder.

After the pilot, `claudectl server migrate --all --exclusive-owner` moves every remaining
account on a machine in one run (stop every Claude session there first; the command refuses
while one runs). Read the summary table: rerun for `lost-reply` and `failed:fenced`, run
`claudectl server migrate --abort <alias>` for `superseded` or `gone`, and stop and report
for `unrotated`. A row `migrated (log out the live login)` means the live login on that
machine holds a retired grant: run `claude auth logout` there; claudectl never deletes it. 7. **Verify** on the Mac and on the devbox: `claudectl server run <alias> -- -p "say ok"` across
one access-token renewal, then `claudectl server status <alias>`.

## Alerts

| Alert                                | First checks                                                                                                            |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
| `ClaudectlServerUnavailable`         | `kubectl -n claudectl get pods`; pod logs; `/ready` fails while the database schema is missing or a pod drains          |
| `ClaudectlCredentialOperationFailed` | the `reason` label and the structured logs (`{"operation":...,"reason":...}`); `claudectl-server audit` for the account |

Reasons and what they mean:

- `account_unavailable_or_login_required`: a refresh failed or its outcome is uncertain. The
  server never replays an uncertain exchange. Run `claudectl server renew <alias>`.
- `refresh_in_progress`: another replica holds the account's lease. Machines retry; it clears
  within 2 minutes even if that replica died.
- `usage_login_required`, `usage_failed`: usage reads failed; tokens still work.
- `registry_unavailable`, `persistence_failed`, `audit_unavailable`: the database is unreachable
  or refused a write. Check the RDS instance and the `claudectl-postgres` secret.

## Operations

The image has no shell; run the binary in a server pod, where `DATABASE_URL` is set:

```shell
kubectl -n claudectl exec deploy/claudectl -c server -- /claudectl-server users --key-file /keys/vault-key
kubectl -n claudectl exec deploy/claudectl -c server -- /claudectl-server revoke --key-file /keys/vault-key --machine <machine-id>
kubectl -n claudectl exec deploy/claudectl -c server -- /claudectl-server audit --key-file /keys/vault-key
```

- **Lost machine:** `claudectl server revoke <machine-id>` from another enrolled machine, or the
  operator command above. A token already issued stays valid until it expires.
- **Remove an account:** `claudectl server remove <alias>`. The grant is erased; work that
  started before the delete cannot recreate it.
- **Shutdown:** a pod drains on SIGTERM within 120 s; in-flight refreshes finish first.

## Rollback

- **Server version:** revert the digest pin; Argo CD rolls back. Schema changes only expand, so
  an older server reads the newer schema until its `min_reader` says otherwise.
- **Whole service:** delete the Argo CD application. Keep the database and the vault key: they
  hold the only refresh grants of migrated accounts.
- **A migrated account:** do not restore an old local copy. Run `claudectl server renew <alias>`,
  or sign in again with `claudectl login` and leave the server account deleted.
