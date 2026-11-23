# Claudectl

Claudectl manages Claude Code logins saved on a machine or held by an account
server. It chooses accounts with capacity and helps sessions continue when
access changes.

## Language

### People and machines

**Company user**:
A person who signs in to the account server with their company sign-in. The
server keys the user by the sign-in identity and checks the company email
against the allow list.

**Machine**:
An identity authorized to obtain access tokens from the account server for a
company user. It represents an enrolled computer or a shared credential that
lets unattended jobs connect directly.

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
A local record of a Claude login saved under an alias. It can remain after
migration retires its usable credentials.
_Avoid_: local account

**Active profile**:
The local profile named by claudectl's active profile marker. Claudectl sets
the marker when activating a profile or saving the live login, and a direct
Claude Code sign-in can change the live login independently.

**Server account**:
A Claude login held on the account server under one company user and alias.
Machines enrolled by that user can use the account.
_Avoid_: remote profile

**Default server account**:
The server account for plain Claude Code launches when claudectl's launcher
is enabled, configured for server use, and found first in the shell's search
path.

**Migration**:
Transferring ownership of Claude credentials from a saved profile or the
matching live Claude Code login to the account server. The machine keeps the
profile record after retiring the profile's saved credentials.

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
An account claudectl can choose automatically because it has current usage
data, room within its limits, more than five percent weekly headroom, and
extra usage confirmed off. A server account must also be available, and a
local profile needs a known subscription plan.

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
A hold that defers automatic restarts for one supervised Claude Code run on a
server account until the user ends it. The request comes from within the run
and uses that run's identity.
