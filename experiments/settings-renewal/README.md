# Synthetic settings renewal checks

These scripts run the real, pinned Claude binary against fake TLS/provider
endpoints. They never log in or use a real credential. Do not remove their network
or credential-store restrictions. Python 3 and OpenSSL are required.

Linux requires user, mount and network namespaces:

```sh
CLAUDECTL_PROBE_PARENT_NET="$(readlink /proc/self/ns/net)" \
CLAUDECTL_PROBE_PARENT_MNT="$(readlink /proc/self/ns/mnt)" \
unshare -Urnm python3 experiments/settings-renewal/linux.py \
  file_proactive file_401 file_expired file_outage file_missing file_malformed file_tui
```

For the full launcher/tool test, build `claudectl` with `cargo build --release --locked` and add
`CLAUDECTL_PROBE_LAUNCHER="$PWD/target/release/claudectl"` to that environment, then
run `supervised.py` under the same `unshare -Urnm` restriction.

macOS requires `/usr/bin/sandbox-exec` and Homebrew OpenSSL:

```sh
python3 experiments/settings-renewal/mac.py
```

Set `CLAUDECTL_PROBE_BINARY` to the tested binary's absolute path when needed.
The Mac harness blocks real Keychain access and substitutes a synthetic command
response. Its evidence establishes credential precedence at that boundary, not
native Keychain ACL behavior. All expiry/rejection responses are simulated.

Reports contain generation labels, result types, and process/session metadata.
No output from these experiments establishes subscription billing eligibility.
