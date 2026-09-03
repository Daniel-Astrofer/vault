# Architecture boundaries

The enforced dependency direction is:

```text
apps → API → bootstrap composition root → adapters → vault-application → vault-domain
```

`vault-domain` contains value types, policy configuration, financial
invariants, and state transitions. It does not import an async runtime, HTTP,
TLS, filesystem, Bitcoin, FROST, Tor, TPM, TEE, environment variables, or
logging libraries.

`vault-application` contains use cases and small ports. `SignMessage`, for
example, depends on `SigningPort`; it has no knowledge of FROST, local share
state, TEE, or network transport.

`vault-adapters` contains FROST, Bitcoin, storage, TLS, attestation and peer
transports, grouped by the technology boundary under `src/`. `vault-api`
contains HTTP/Unix-socket translation, split into independently bound route
sets and route-facing services.
`vault-bootstrap` owns configuration, production gates, and dependency wiring.
It is the sole location where concrete adapter implementations are selected;
the API receives the already-composed runtime and performs only protocol
translation.
`vault-core` is now only a backwards-compatible facade for existing callers.
Bitcoin address parsing, script construction, and PSBT decoding live in
`vault-adapters::bitcoin`; the domain retains only policy and network labels.

## Rules of change

1. Add a new business rule to `vault-domain`; it must remain deterministic and
   free of I/O.
2. Add a workflow to `vault-application/src/use_cases`; introduce or extend a
   narrow trait in `ports` only for a required external capability.
3. Implement that trait in one `vault-adapters` technology directory.
4. Wire concrete implementations only in `vault-bootstrap/runtime`.
5. Expose a workflow through `vault-api/routes`, keeping protocol DTOs and
   authentication translation at the boundary.

No layer may skip inward: the domain never imports application or adapters;
application never imports API, bootstrap, or adapter implementations.

`tests/architecture_boundaries.rs` prevents accidental imports or manifest
dependencies that would reverse these boundaries.
