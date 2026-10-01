# Git history archives v2

Scope: store exact, self-contained Git bundle bytes for each repository of a
Cell release. This is an archive API, **not release authorization**, build
verification, a consensus ledger, or a signer activation API. The JSON source
archive v1 API remains unchanged.

## Identity and transport

The existing protected Admin router requires `X-Vault-Token` on every route.
Prefer its private Unix socket. The optional legacy Admin TCP listener has no
native mTLS enforcement: do not expose it directly or describe it as mTLS.
No new unauthenticated route is introduced.

The archive identity is the tuple `(releaseId, repositoryId)`. A Cell can
therefore retain core, kfe, node, vault, admin, clients, contracts, shared,
web-page and deploy histories under one release ID. Disk record names hash a
JSON tuple rather than ambiguous concatenated identifiers. Bundle blobs are
deduplicated by SHA-256. All identifiers are validated before path construction.

Routes, where `BASE=/admin/v2/releases/{release_id}/repositories/{repository_id}/git-archive`:

- `GET /admin/v2/git-archives/capability`: availability of storage and verifier.
- `PUT BASE/approval`: immutable operator binding of exact digest and commit.
- `PUT BASE`: raw `application/x-git-bundle` or `application/octet-stream` bytes.
- `GET BASE/receipt`: locally recorded verification result.
- `GET BASE`: original bytes with digest ETag, approved commit and repository
  headers. The blob is rehashed before handling conditional requests, including
  304 responses. Range requests are not implemented.

Approval shape:

```json
{
  "archiveVersion": 2,
  "releaseId": "release-001",
  "repositoryId": "core",
  "commit": "<40 lowercase sha1 or 64 lowercase sha256 hex>",
  "objectFormat": "sha1",
  "bundleSha256": "sha256:<64 lowercase hex>",
  "retentionPinned": true
}
```

The approval must be provisioned independently of untrusted bundle content.
Unknown fields, unsupported object formats and non-pinned retention are
rejected. Retrying identical bytes returns the original receipt; an identity
cannot be rebound to different bytes or commits, even after restart. There is
no deletion or garbage collection API. Capacity and retention provisioning
remain operator responsibilities; aggregate disk quota is not implemented.

## Git verification boundary

Configure `VAULT_ARCHIVE_GIT_PATH` to an absolute, independently installed Git
binary and `VAULT_ARCHIVE_GIT_SHA256` to its approved SHA-256. No archive can
select the executable. Linux x86_64/aarch64 with Git >=2.43 is required by this
implementation; the minimum version is a compatibility floor, not a statement
that every such build is secure. Operators must approve a patched binary.
Missing configuration, wrong pins or unavailable sandboxing fail closed.

Verification uses the same opened executable inode, an empty private scratch
repository and fixed plumbing commands. It verifies pack integrity, complete
object connectivity, the approved commit type, and reachable history count.
It does not fetch, clone, check out, run source, hooks, filters, submodules or
arbitrary helper executables. Global/system Git config, replacements and lazy
fetch are disabled. Network socket syscalls are denied in the child. Time,
CPU, memory, output, descriptors, pack bytes and object count are bounded.
The upload limit is 32 MiB, at most 50,000 packed objects and 64 advertised refs.
Prerequisite-dependent and filtered bundles are rejected.

Original bytes and records are durably published without replacement. Reads
reject symbolic links, multiple hard links and nonregular files. Local storage
ownership remains a trust boundary; no claim is made that an owner/root cannot
change evidence. A tampered blob gives an error rather than an automatic repair.

Verification receipts are local records, **not quorum-signed receipts**.
Clients must independently compare bytes against a release digest authorized
through their protected TUF/governance trust anchors. A Byzantine Vault may
withhold data, lie about availability or return older data; it cannot make
different bytes pass an independently pinned SHA-256. Use multiple independent
mirrors for availability. A digest or valid Git history alone does not prove
release safety, source-to-image provenance or compatibility.

## Verification

Run `cargo test -p vault-api -p vault-adapters -p vault-domain git_archive` with
default production features. Adapter integration tests use a real independently
pinned `/usr/bin/git`, create a two-commit bundle and reject truncation, missing
history and wrong pins. They never skip those checks because Git is unavailable.
API tests separately exercise authentication, repository binding, unavailable
verification, and corruption before conditional-download responses. Synthetic
API fixtures are not presented as Git-verification evidence.
