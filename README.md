# sh-keyring

A small Bash library for retrieving secrets from whatever source happens to be
available, with transparent caching in the macOS Keychain.

`set_key FOO` resolves the value of `FOO` from the first source that has it —
the current environment, the macOS Keychain, 1Password, or AWS Secrets
Manager — and exports it. Values fetched from a remote vault are cached in the
Keychain so subsequent lookups are fast, and the cache expires after 12 hours
so rotated secrets get picked up.

## Requirements

- **Bash** (sourced, not executed).
- **macOS** — the Keychain cache uses the `security` CLI, and expiry uses BSD
  `date` (`date -j -u -f ...`).
- Optional secret sources, used only if their CLI is installed:
  - [1Password CLI](https://developer.1password.com/docs/cli/) (`op`)
  - [AWS CLI](https://aws.amazon.com/cli/) (`aws`)

## Usage

Source the library, then call `set_key` with the name of the variable you want
populated:

```bash
source /path/to/sh-keyring.shlib

set_key MY_API_KEY
echo "${MY_API_KEY}"
```

The library is safe to source repeatedly in one shell — an include guard makes
re-sourcing a no-op.

### Resolution order

`set_key` tries these sources in order and uses the first that yields a
non-empty value:

1. **Environment** — the variable's existing value, if already set.
2. **macOS Keychain** — a previously cached value (see caching below).
3. **1Password** — the password field of the item whose title matches the
   variable name.
4. **AWS Secrets Manager** — secret ID `engineering/common/<VAR_NAME>` under the
   `eng-common-secrets-devt` profile.

Values fetched from 1Password or AWS are written back into the Keychain so the
next run is a fast local hit. The local sources (environment, Keychain) are not
re-cached.

### Caching and expiry

Cached Keychain entries expire after **12 hours**. Before resolving, `set_key`
drops a stale cache entry so an expired secret is re-fetched from the remote
vault rather than served from the cache. Expiry reads only the entry's
modification-date attribute, so it neither unlocks the secret nor triggers an
access prompt. When a stale entry is deleted, the Keychain's deletion report is
emitted on stderr, keeping stdout a clean data channel for callers that use
command substitution.

### Exit status

`set_key` distinguishes "nothing configured" from "something broke" so callers
can react appropriately:

| Status | Meaning | Behavior |
| --- | --- | --- |
| `0` | A source yielded a value; the variable is set and exported. | — |
| `1` | **Absent** — nothing was configured in any source. | Silent. A fresh user who never set up a key is not surprising. |
| `2` | **Errored** — a source was reachable but failed (locked vault, expired credentials, denied Keychain prompt). | Warns on stderr. A configured key that fails to retrieve is the surprising case. |

This three-state convention (found / absent / errored) is shared by every
`get_key_from_*` source function, and `coalesce` propagates the most severe
status seen when no source succeeds.

## Library functions

The library is composed of small, single-purpose functions. The main entry
point is `set_key`; the rest are building blocks.

- `set_key <var>` — resolve, cache, and export a secret (main entry point).
- `coalesce <fn>... [-- arg...]` — return the output of the first function that
  succeeds with non-empty output; otherwise return the most severe status.
- `get_key_from_env <var>` — read a value from the environment.
- `get_key_from_mac <key>` — read a value from the macOS Keychain.
- `get_key_from_1password <key>` — read a value from 1Password.
- `get_key_from_aws <profile> <secret-id>` — read a value from AWS Secrets
  Manager.
- `put_key_in_mac <key> <value>` — store a value in the Keychain.
- `del_key_from_mac <key>` — delete a Keychain entry.
- `expire_key_in_mac <key> <ttl-seconds>` — delete a Keychain entry older than
  the TTL.
- `fetch_and_cache_key_in_mac <key> <fetcher>...` — run a fetcher and cache its
  result in the Keychain on success.
- `probe_key_source <cmd>...` — run a command if its binary exists, classifying
  the outcome as found / absent / errored.

## Testing

Tests are written with [`pytest`](https://docs.pytest.org/) and drive the Bash
functions through subprocesses. Each test runs under a stub-only `PATH`: real
`bash`/`date`/`sed` are symlinked in, while `security`/`op`/`aws` exist only
when a test installs a stub — so every scenario, including "this CLI is not
installed", is deterministic regardless of what is installed on the host.

```bash
pytest tests/
```

The tests are macOS-specific, matching the library's own platform assumptions.