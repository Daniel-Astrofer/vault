# Release compatibility evidence v1

The existing `GET /admin/compatibility` response remains unchanged. It describes
runtime capabilities and is not release acceptance evidence. The new routes use
a Vault-local versioned schema; the pinned `kerosene-contracts` artifact and
FROST protocol are unchanged.

Both routes require the configured operator `X-Vault-Token`. Missing or invalid
tokens return HTTP 401 before body parsing or archive lookup. Use the owner-only
admin Unix socket. The existing optional admin TCP server does not implement
mTLS; a token does not provide transport confidentiality. Responses carry
`Cache-Control: no-store`.

## Archive ingestion

`POST /admin/v1/releases/source-archives` accepts this JSON source bundle:

```json
{
  "formatVersion": 1,
  "releaseId": "vault-release-1",
  "targetSequence": 7,
  "protocolVersion": 1,
  "storageVersion": 1,
  "production": true,
  "features": ["production"],
  "files": [{"path": "src/lib.rs", "contentHex": "6162"}]
}
```

The response is HTTP 200 with `evidenceVersion: 1`, an `archive` receipt containing
`formatVersion`, `releaseId`, `canonicalDigest`, `targetSequence`, and
`archivedAtSecs`, plus `acceptedRelease: false` and `signerActivation: false`.
An identical retry returns the original receipt and archival timestamp. Reusing
a release ID for different bytes, sequence, versions, or claims returns HTTP 409.
Unknown fields, hash text, unsupported bundle formats and malformed bundles
return HTTP 400. Oversized HTTP bodies return HTTP 413. Archive clock failure
rejects ingestion.

This is an inert archive format of regular file bytes. Tar, zip, compression,
links, modes, extraction destinations and Git objects are not accepted. No
source files are materialized, evaluated, built, imported, or executed.

Limits apply before storage: 4 MiB HTTP body and canonical blob, 256 files,
256 KiB decoded bytes per file, 2 MiB total decoded content, 240 bytes per path,
32 feature claims of 1..64 bytes each. Release IDs use 1..128 ASCII letters,
digits, hyphens or underscores. Paths use ASCII letters, digits, `/`, `_`, `-`
and `.`; absolute paths, backslashes, drive prefixes, empty components, `.`/`..`
components, `.git` components, duplicate paths and file/directory conflicts are
rejected. Link or other extension fields are rejected rather than ignored.

The SHA-256 canonical digest covers the literal UTF-8 prefix
`vault-source-bundle-v1\n` followed by compact JSON, without a trailing newline.
Field order is exactly the example's order. Features are sorted and unique;
files are sorted by ASCII path and `contentHex` is lowercase. Whitespace and
input object/file order do not change identity. All metadata claims and file
bytes are bound, including release ID and target sequence. Protocol version
claims describe mesh negotiation; storage version claims describe the release
snapshot format, not every storage adapter or a database migration guarantee.

## Authenticated compatibility read

`GET /admin/v1/releases/{releaseId}/compatibility?canonicalDigest={sha256Hex}&targetSequence={positiveU64}`

Both query fields are required. The server reopens the immutable receipt/blob,
verifies regular-file constraints, recomputes the digest and canonical form,
and checks the requested identity against stored evidence. An unarchived ID
returns HTTP 404; a valid but different digest or sequence returns HTTP 409.
Malformed queries or IDs return HTTP 400. Digest corruption returns HTTP 503;
other malformed storage evidence fails closed without a successful report.

HTTP 200 returns `evidenceVersion: 1`, the bound `releaseId`, `canonicalDigest`
and `targetSequence`, `checks`, `compatible`, and `signerActivation: false`.
Version observations are `currentProtocolVersion` from the active constitution,
`currentStorageVersion` from the validated release snapshot format (currently 1),
`currentShareEnvelopeVersion` from the constitution, and
`currentHybridEnvelopeVersion` from the implemented envelope format. Unknown
constitution versions are null, and an unknown protocol check is `unknown`.
These observations do not inspect or migrate custody material.

Checks have values `passed`, `failed`, or `unknown`:

| Check | Observation |
| --- | --- |
| `archiveIntegrity` | Canonical bytes and receipt identity verified |
| `releaseBinding` | Requested release/digest/sequence match storage |
| `protocolVersion` | Claimed version equals observed mesh protocol version |
| `storageVersion` | Claimed release snapshot version equals implementation |
| `productionPolicy` | Production claim/features and actual runtime meet the policy below |
| `featureSupport` | Every claimed feature is enabled in the running build |
| `freshness` | Valid observation clock, archive not future-dated, expiry representable |
| `independentBuildVerification` | Unknown: no authenticated independent rebuild evidence |
| `authenticatedReleaseApproval` | Unknown: no verified release-governance signatures |
| `targetSequenceAuthorization` | Unknown: no authenticated monotonic release sequence authority |

Production policy requires a production build without dealer support, production
ceremony, distributed-wire DKG, hardened runtime, no dealer request, simulated
attestation or staging stub, and no lab timelock override. Declared features
must include `production` and cannot contain `lab` or `dealer` (case-insensitive).
Claims are checked as claims; they do not prove how an artifact was built.

`observedAtSecs`, `expiresAtSecs`, and `maxAgeSecs: 300` describe the live report;
`archivedAtSecs` describes immutable source archival, which need not be recent.
Consumers must verify the binding and reject reports outside
`observedAtSecs <= now < expiresAtSecs`, or with any failed/unknown check.
Fetch a new report after runtime changes. This HTTP evidence is authenticated
in transit; it is not a detached cryptographic attestation or replay-proof
authorization token.

`compatible` is true only when every check passes. Because independent build,
governance and sequence evidence are unavailable, v1 currently always reports
incompatible. Neither a well-formed hash, feature declarations, a source bundle,
nor legacy lab cosign/rebuild/allowlist labels supply that missing evidence.
`gitHistory: "unavailable"` explicitly reports the lack of verified history.

## Persistence and API boundaries

Storage reuses the isolated release mesh under `VAULT_DATA_DIR/release/`:
`blobs/{canonicalDigest}` stores canonical source bytes;
`source_archives_v1/{SHA256(releaseId)}` stores the immutable receipt. Existing
release candidates and allowlists retain their schema and use-case signatures.
The archive routes never create candidates, cosign releases, modify allowlists,
activate signers, or touch shares, nonces, DKG, reshare or settlement.

Blob writes now enforce actual content hashes, size bounds, and immutable
publication. Existing lab rebuild fingerprints remain unchanged; their stored
synthetic bytes now match the fingerprint. Previously stored mismatched lab
blob bytes are rejected on read and are not silently repaired. Unknown release
snapshot versions are refused. No existing archive is overwritten or migrated.

See [release evidence threat model](../security/RELEASE_EVIDENCE_THREAT_MODEL.md)
and [production gates](../STATUS.md) for approval boundaries and residual risks.
