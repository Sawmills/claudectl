# Claudectl

Claudectl manages Claude Code logins saved on a machine or held by an account
server. It chooses accounts with capacity and helps sessions continue when
access changes.

## Language

### People and machines

**Company user**:
A person identified by their company's sign-in on the account server.

**Machine**:
A computer enrolled with the account server to use a company user's accounts.

**Account server**:
The service that holds Claude refresh credentials and supplies access tokens to
enrolled machines.

**Machine revocation**:
Ending a machine's ability to obtain new access tokens from the account server.
Tokens issued before revocation can remain usable until they expire.

### Accounts

**Alias**:
A name assigned to a profile or server account.
_Avoid_: account name alone

**Profile**:
A Claude login saved under an alias on one machine.
_Avoid_: local account

**Active profile**:
The profile selected as the machine's live local Claude Code login. Claude Code
manages refresh for that login.

**Server account**:
A Claude login held on the account server under one company user and alias.
Machines enrolled by that user can use the account.
_Avoid_: remote profile

**Default server account**:
The server account selected for new ordinary Claude Code launches on a machine.

**Migration**:
Moving a local profile onto the account server so the server takes over
refreshing the login.

**Login renewal**:
A new Claude sign-in that gives an existing server account fresh credentials for
the same login.
_Avoid_: re-login

### Usage and selection

**Usage window**:
A period with its own Claude usage limit and reset, such as five hours or a week.

**Weekly headroom**:
The percentage of the weekly usage allowance still available.

**Extra usage**:
Usage beyond the included Claude allowance that can incur charges when enabled.

**Eligible account**:
An account that can be chosen automatically. It has current usage data, room
within its limits, more than five percent weekly headroom, and extra usage
confirmed off.

**Limit-reset offer**:
A provider offer that can restore capacity for specified usage limits before
their usual reset. Each offer has its own conditions and availability.

### Sessions

**Token renewal**:
Replacing a session's expiring or expired access token with fresh access for the
same server account. Claude Code takes up the replacement when it restarts.

**Authentication recovery**:
An attempt to resume a session on the same server account with fresh access
after that session encounters an authentication failure.

**Account failover**:
A restart that attempts to resume an interactive session on another eligible
server account after a confirmed usage limit.

**Production hold**:
A user-declared hold on a running Claude Code session that defers its automatic
restarts until the hold ends.
