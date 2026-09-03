# Repository layout

```text
apps/                 executable entry points
crates/               independently owned architectural layers
tests/                contract, application, adversarial, integration and E2E suites
scripts/              ceremony, lab, staging and security operations
docs/                 runbooks and architecture records
var/                  ignored local certificates, ceremony output and node state
```

`var/` is intentionally outside source and test-fixture trees. Its material is
local-only and may include credentials, shares, nonces or ceremony transcripts.
Use the scripts' `VAULT_*_OUT` variables to choose a different location when
needed; never add generated runtime material to Git.

The production executable is `apps/kerosene-vault`. The workspace-root package
is retained as a compatibility facade and integration-test harness.

## Layer ownership

```text
crates/vault-domain/src/
  identity/ membership/ epoch/ intent/ psbt/ signing/ policy/ quorum/ ledger/ release/
crates/vault-application/src/
  use_cases/            orchestration of business workflows
  ports/                required capabilities, expressed as traits
crates/vault-adapters/src/
  attestation/tee/      SGX, SEV-SNP and quote verification
  frost/                distributed DKG, FROST signing and resharing
  bitcoin/              PSBT validation and channel injection
  storage/              durable, in-memory and sealed-share stores
  http/                 peer/quorum transport and operational controls
  mtls/ identity/ crypto/ system/
crates/vault-api/src/
  routes/               public mesh and separately bound admin routes
  services/             route-facing application services
crates/vault-bootstrap/src/
  config/               parsed configuration model
  runtime/              dependency composition root
  security/             production-only build gates
```

Each directory has one responsibility. Cross-cutting concerns communicate
through `vault-application::ports`, never by importing an adapter from domain
or a use case.
