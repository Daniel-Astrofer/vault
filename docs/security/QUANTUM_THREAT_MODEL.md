<!--
Kerosene documentation metadata
status: review-required
audience: internal/restricted
owner: vault
source_of_truth: vault
last_reviewed: 2026-09-03
-->

# Quantum Threat Model — Kerosene Vault Mesh

> **Document Status:** Draft  
> **Last Updated:** 2026-07-30  
> **Related:** `docs/PQ_KEY_ARCHITECTURE.md`, `docs/history/VAULT_IMPLEMENTATION_PLAN.md`

## 1. Adversary Model

### 1.1 Passive Capture Today (Harvest-Now-Decrypt-Later)

The primary near-term threat is **passive bulk capture** of network traffic and stored data by adversaries who do not yet possess a CRQC (Cryptographically Relevant Quantum Computer) but plan to decrypt the data once one becomes available.

| Threat Vector | Data Captured | Window |
|---|---|---|
| Wire sniffing (ISP, backbone, BGP hijack) | DKG/reshare messages, Intents, audit records | Indefinite storage |
| Compromised backup media | Sealed shares, identity seeds, DKG transcripts | Until rotation |
| Data exfiltration from compromised vault | All key material, session transcripts | Until revocation |
| Compromised TLS termination proxy | Plaintext after TLS decryption | Until infrastructure cleanup |

**Assumption:** Any data transmitted or stored today may be recorded and stored by adversaries for future decryption.

### 1.2 Future Active Attack with CRQC

Once a CRQC is available, an adversary gains:

- **DLP (Discrete Logarithm Problem) break** — recover secp256k1 private keys from public keys
- **EC-DH break** — decrypt any past/future X25519 key exchange
- **EC-DSA break** — forge Ed25519 signatures
- **No material advantage against:**
  - ML-KEM-768 (lattice-based KEM, NIST PQC)
  - ML-DSA-65 (lattice-based signatures, NIST PQC)
  - AES-256 / ChaCha20-Poly1305 (symmetric, ~128-bit quantum security via Grover)
  - SHA-384 / SHA-3-256 (hash functions, ~192-bit quantum security via Grover)

### 1.3 Timeline Assumptions

| Horizon | Expected Capability | Impact |
|---|---|---|
| 2026–2030 | No CRQC; academic qubit records (10³–10⁴ logical qubits) | Low; prepare PQ infrastructure |
| 2030–2035 | Possible CRQC for specific problems; 10⁵+ logical qubits | High if unmitigated |
| 2035+ | General-purpose CRQC plausible | Critical |

**Kerosene positioning:** PQ infrastructure must be operational **before go-live** (2026–2027) so that data captured from day one is protected.

---

## 2. Protected Assets

Release compatibility observations and source archives are separate from the
release-manifest signature goal below. Their current implementation reports
missing production approval/build/sequence verification as unknown and never
activates a signer. See the [release evidence threat model](RELEASE_EVIDENCE_THREAT_MODEL.md).

| Asset | Algorithm | PQ Protection | Sensitivity |
|---|---|---|---|
| **FROST shares** (secp256k1) | FROST-256 | ML-KEM-768 sealed envelope | Secret key material; total fund loss if exposed |
| **DKG transcripts** | FROST DKG wire | HybridEnvelope (X25519 + ML-KEM-768) | Contain secret share material during DKG |
| **Reshare messages** | FROST reshare wire | HybridEnvelope (X25519 + ML-KEM-768) | Secret share material during rotation |
| **Backups** (sealed shares, seeds) | AES-256-GCM / TPM-sealed | ML-KEM-768 wrapped key | Long-term key material |
| **Vault identity keys** (Ed25519 + ML-DSA-65) | Ed25519, ML-DSA-65 | ML-DSA-65 (PQ signature) | Authentication; impersonation if compromised |
| **Vault transport keys** (X25519 + ML-KEM-768) | X25519, ML-KEM-768 | ML-KEM-768 (PQ KEM) | Wire secrecy |
| **Audit logs** | Ed25519 + ML-DSA-65 | ML-DSA-65 (PQ signature) | Long-term non-repudiation |
| **Session transcripts** (DKG, reshare, intent) | X25519 + ML-KEM-768 envelope | ML-KEM-768 | Captured today, sensitive tomorrow |
| **Vault constitution** | Ed25519 + ML-DSA-65 | ML-DSA-65 (PQ signature) | Governance integrity |
| **Release manifests** | Ed25519 + ML-DSA-65 | ML-DSA-65 (PQ signature) | Software supply chain |

### 2.1 Data Freshness

Data classified as "protected" above uses **hybrid encryption** (X25519 + ML-KEM-768) or **hybrid signatures** (Ed25519 + ML-DSA-65). This means:

- Classical-only break → still protected by PQ component
- PQ-only break → still protected by classical component (but fallback is temporary)
- Both broken → full compromise (plan for migration)

---

## 3. Assets NOT Protected by PQ

### 3.1 UTXOs Taproot On-Chain

Bitcoin Taproot addresses (`tb1p`/`bc1p`) expose a 32-byte secp256k1 x-only public key in the witness program (BIP 341). This is a **consensus-level limitation** — the Kerosene vault mesh cannot change Bitcoin's address format.

| Detail | Value |
|---|---|
| Public key exposed | secp256k1 x-only (32 bytes) |
| Protocol | Taproot (BIP 341) |
| Vulnerability | DLP break via CRQC → private key recovery |
| Mitigation path | Bitcoin consensus change only (BIP 360, P2MR, or similar) |
| Kerosene control | None on-chain |

**Consequence:** An on-chain UTXO's security depends entirely on the classical secp256k1 DLP assumption. Even if the Kerosene vault mesh uses PQ internally, the deposited funds' on-chain address is **not PQ-protected**.

#### 3.1.1 What This Means in Practice

| Scenario | On-Chain Security | Off-Chain Security |
|---|---|---|
| CRQC available today | UTXOs spendable by adversary (funds lost) | Vault identity, transport, audit still PQ-protected |
| ML-KEM broken | No direct impact on UTXOs | Identity/transport need algorithm migration |
| ML-DSA broken | No direct impact on UTXOs | Identity/transport need algorithm migration |
| secp256k1 broken (classical) | UTXOs spendable by adversary (funds lost) | Identity/transport still PQ-protected |

### 3.2 Why This Separation Is Intentional

The Kerosene vault mesh **never exposes PQ public keys on-chain**. The on-chain footprint is:

```
Taproot script path (if any) → script_hash commitment
Taproot key path → secp256k1 x-only public key
```

ML-KEM public keys, ML-DSA public keys, and hybrid identity material are transmitted **only in the mesh's private P2P protocol** over encrypted channels. They never appear in a Bitcoin transaction.

---

## 4. NIST Security Categories

### 4.1 Target Levels

| Primitive | Algorithm | NIST Level | Bit Security (Classical) | Bit Security (Quantum) |
|---|---|---|---|---|
| **KEM** | ML-KEM-768 | **Level 3** | 192 | 128 |
| **Signatures** | ML-DSA-65 | **Level 3** | 192 | 128 |
| **Classical KEM** | X25519 | Not PQ | 128 | 0 (broken by CRQC) |
| **Classical signatures** | Ed25519 | Not PQ | 128 | 0 (broken by CRQC) |
| **Symmetric** | AES-256-GCM | — | 256 | 128 (Grover) |
| **Symmetric** | ChaCha20-Poly1305 | — | 256 | 128 (Grover) |
| **Hash** | SHA-384 | — | 384 | 192 (Grover) |
| **Hash** | SHA-3-256 | — | 256 | 128 (Grover) |

**Why Level 3?** Level 3 matches AES-192 in brute-force security. For the Kerosene threat model:
- Level 5 (ML-KEM-1024, ML-DSA-87) offers no meaningful advantage against harvest-now-decrypt-later (128-bit quantum security is already below feasible attack cost)
- Level 3 is the NIST-recommended baseline for "conservative security" at standard protection needs
- Migration to Level 5 is possible in the future without protocol change (key size increases only)

### 4.2 Policy Enforcement

The vault constitution enforces minimum capabilities, not algorithm names:

```yaml
minimum_policy:
  pq_kem_security_category: 3
  pq_signature_security_category: 3
  symmetric_key_bits: 256
  minimum_quantum_work_factor_bits: 128
  hybrid_kem_required: true
  hybrid_signature_required: true
  downgrade_protection: true
```

Suites failing to meet these minimums are rejected at boot and at message validation.

---

## 5. Risk Window

### 5.1 Data Lifetime vs. Quantum Timeline

| Data Type | Lifetime | Risk Window | Mitigation |
|---|---|---|---|
| FROST share (current) | Until reshare | ~1 day (daily reshare) | Rotated before CRQC relevant |
| DKG transcript | Seconds (session) | Indefinite if captured | HybridEnvelope protects at capture time |
| Reshare transcript | Seconds (session) | Indefinite if captured | HybridEnvelope protects at capture time |
| Sealed backup share | Years (cold storage) | Indefinite | ML-KEM-768 seal + periodic rotation |
| Identity key pair | 90–365 days | Until revocation | Atomic rotation + quorum revocation |
| Transport static key | Per key epoch (1 day) | Until epoch end | Ephemeral per message; static rotates daily |
| Audit log entry | Permanent | Indefinite | ML-DSA-65 signature at creation time |
| Session TLS traffic | Per connection | Indefinite if captured | Application-layer HybridEnvelope (not just TLS) |

### 5.2 Key Epoch and Rotation Schedule

| Domain | Rotation Cadence | Trigger |
|---|---|---|
| `custody/` | Daily (reshare) | Day-advance hook |
| `identity/` | 90 days (or on compromise) | Quorum decision |
| `transport/` | Daily (static key epoch) | Day-advance hook |
| `audit/` | 1 year (or on compromise) | Quorum decision |

### 5.3 Risk Acceptance

The vault mesh accepts the following residual risks:

1. **On-chain UTXO exposure:** Mitigated by quantum migration controller (State Q0–Q6) that can sweep funds to PQ-safe destinations when CRQC is imminent.
2. **Classical-only fallback in lab:** Lab deployments use a different protocol identifier and cannot connect to production. No quantum risk.
3. **Compromised RNG:** If vault bootstrapping uses weak entropy, all derived keys (including PQ) are compromised. Mitigated by TPM/TEE hardware RNG and KAT at boot.

---

## 6. Consequences and Domain Separation

### 6.1 Clear Separation: Bitcoin Custody vs. Identity/Transport PQ

| Domain | Classical | PQ | Custody Impact |
|---|---|---|---|
| `custody/` | FROST secp256k1 | None (on-chain limitation) | Total fund loss if CRQC available |
| `identity/` | Ed25519 | ML-DSA-65 | Impersonation, no fund loss |
| `transport/` | X25519 | ML-KEM-768 | Traffic decryption, no fund loss |
| `audit/` | Ed25519 | ML-DSA-65 | Audit forgeries, no fund loss |

**Key principle:** Compromise of identity, transport, or audit keys **does not** expose FROST shares or allow fund movement. Custody signing requires:
1. FROST threshold (2/3) from `custody/` shares
2. Valid hybrid Intent from `SettlementAuthorities` (not vault identity)
3. Independent PSBT validation

### 6.2 What Happens If PQ Is Broken

If ML-KEM-768 or ML-DSA-65 is broken (e.g., lattice reduction breakthrough):

| Broken Primitive | Impact | Immediate Action |
|---|---|---|
| ML-KEM-768 | Transport secrecy lost; DKG/reshare transcripts decryptable if captured | Rotate to alternative PQ KEM; hybrid construction still protects past data via X25519 component |
| ML-DSA-65 | Identity signatures forgeable; vault impersonation possible | Rotate identity keys to new PQ signature scheme; revoke old keys via quorum |
| Both ML-KEM-768 + ML-DSA-65 | Full PQ protection lost; fall back to classical-only (temporary) | Emergency governance to deploy new PQ suite; hybrid composition buys time |

**Hybrid safety guarantee:** The AND composition ensures that breaking either the classical OR the PQ component still leaves the other protecting the system. Only breaking **both** simultaneously compromises security.

### 6.3 What Happens If Classical Is Broken

If secp256k1 DLP or Ed25519 is broken (classical cryptanalytic breakthrough, not quantum):

| Broken Primitive | Impact | Immediate Action |
|---|---|---|
| secp256k1 DLP | Bitcoin funds lost on-chain | Quantum migration sweep (Q4/Q5) to alternative address format; PQ component unchanged |
| Ed25519 | Vault identity forgeable (classical only) | Still protected by ML-DSA-65; rotate Ed25519 component at next key epoch |
| X25519 | Wire secrecy lost (classical only) | Still protected by ML-KEM-768; rotate X25519 component at next transport epoch |
| SHA-384 / SHA-3 | Transcript hash collisions possible | Rotate to stronger hash; hybrid envelope includes hash binding per session |

### 6.4 No False Sense of Protection

The vault mesh **explicitly documents and communicates** these limitations:

- **To operators:** Warning at boot if on-chain addresses are in use without PQ migration plan
- **In documentation:** Clear separation of custody vs. identity/transport security boundaries
- **In the constitution:** `quantum_migration` state must be configured before go-live
- **In incident response:** Procedures for each scenario (Section 6.2, 6.3) documented before deployment

---

## 7. Summary of Security Posture

| Property | Classical Only | Hybrid (Current) | PQ Only |
|---|---|---|---|
| Wire secrecy (captured today) | Broken by CRQC | Protected (X25519 + ML-KEM-768) | Not applicable |
| Wire secrecy (future traffic) | Broken by CRQC | Protected (as long as either stands) | Protected |
| Vault authentication | Broken by CRQC | Protected (Ed25519 + ML-DSA-65) | Protected |
| Bitcoin custody on-chain | Broken by CRQC | Exposed (secp256k1 in witness) | Not feasible today |
| Audit integrity | Broken by CRQC | Protected (Ed25519 + ML-DSA-65) | Protected |
| DKG/reshare transcripts | Broken by CRQC | Protected (HybridEnvelope) | Protected |

**Bottom line:** PQ protects everything except the on-chain UTXO. The on-chain limitation is a Bitcoin consensus constraint, not a Kerosene design flaw.
