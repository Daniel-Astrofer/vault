# Release evidence and source archive threat model

Scope: the versioned operator evidence surface and local release blob store.
An attacker may submit malicious bundles, fabricated hash/feature/version
claims, mismatched release/sequence bindings, or replay a saved response. The
storage owner and root remain trusted for filesystem ownership and capacity;
local blobs and receipts are not a distributed authenticated release ledger.

Controls:

- Operator token authentication precedes ingestion and compatibility reads.
  Comparisons use constant-time equality of fixed-size token digests. The
  owner-only Unix socket is the intended transport; optional existing TCP has
  no implemented mTLS. The token grants both archival and read access, without
  per-operator attribution or a separate upload role.
- A strict versioned source bundle admits only bounded regular-file bytes.
  Links, traversal, absolute paths, Git metadata, duplicate paths and
  file/directory conflicts are rejected. There is no unpacking, decompression,
  shell invocation, build execution, hook invocation or network dependency
  fetch. Source code is inert even when it contains executable scripts.
- Canonical SHA-256 identity binds release ID, sequence, metadata and source.
  The immutable ID receipt prevents an operator from replacing a release with
  different content. Reads recompute digest and canonical identity; hash text
  alone never establishes release compatibility.
- Blob publication uses a random `create_new` temporary regular file, file
  fsync, an atomic no-replacement link publication, temporary-name removal and
  directory fsync. Stored bytes have mode 0400. Existing bytes must match on
  retry; no archive destination is truncated or overwritten. Read paths reject
  symlink components, use `O_NOFOLLOW`, reject hard links and non-regular files,
  and enforce a byte bound even if the file grows during the read.
- Runtime/version checks report only inspected facts. Missing independently
  verified production builds, governance signatures and sequence authorization
  stay unknown, hence incompatible. Feature declarations and existing lab
  signature/rebuild labels are not authenticated production approvals.
- Reports bind the requested release/digest/sequence, use a 300-second validity
  window and `no-store`. Missing clocks, future archival timestamps and expiry
  overflow fail freshness. Consumers must enforce binding, expiry and current
  runtime context; responses are not detached signed evidence.

Residual risks: a privileged storage owner can delete or coherently replace
local receipts and blobs. Digest verification detects content mismatch, not
coordinated replacement or rollback by that owner. Ancestor link checks are
not a sandbox against concurrent directory replacement by a privileged local
writer. The archive writer serializes one process; it is not a multi-process
transaction manager. A crash between publishing blob and receipt can leave an
orphan blob. A crash between link publication and temporary-name removal can
leave two links, which reads reject until independently inspected recovery.
Per-bundle bounds do not impose a total disk quota. Capacity management belongs
to the operator; this API provides no deletion, GC, migration or automatic
recovery. HTTP responses contain metadata/checks, never uploaded source bytes
or filesystem paths.

FROST separation: source archival and compatibility observation have no
signing port or release activation dependency. They cannot generate or install
shares, allocate nonces, perform DKG/reshare, sign an Intent/PSBT, change
attestation pins, or grant a binary custody authority. Every successful report
contains `signerActivation: false`; ingestion contains `acceptedRelease: false`.
CI may publish source evidence but cannot activate a signer through these APIs.

Independent approvals remain necessary for production artifact reproducibility
and provenance, authenticated release-governance quorum/timelock and monotonic
sequence authorization, any compatibility contract extension through versioned
`kerosene-contracts`, storage migrations, and deployment. Signer onboarding or
activation requires a separate custody security review, attestation/admission
approval and the existing authenticated FROST ceremonies. This implementation
does not supply any of those approvals.
