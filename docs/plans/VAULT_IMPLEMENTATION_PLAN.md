# Vault Mesh — Plano de Implementacao Restante (v2 — PQ-First)

> **Historical planning record.** The checklist and monorepo paths below are
> retained as migration evidence. They are not current instructions and must
> not be used to operate or release Vault. See [current status](../en/STATUS.md)
> or [estado atual](../pt-BR/STATUS.md).

[SDD Check: Referenced `VAULT_MESH_PLAN.md` — Sections 2, 3, 10-18, Production Gate]
[SDD Check: Referenced `backend/kerosene-vault/docs/DAY_ADVANCE_RESHARE.md` — Full]
[SDD Check: Referenced `backend/kerosene-vault/docs/CEREMONY_TOR.md` — Full]

## Visao Geral

37 itens, 6 tiers. PQ e fundacional — nao futuro. O envelope hibrido, identidade hibrida e migracao quantica sao pre-requisitos de go-live.

---

## Limite Fundamental: Bitcoin Taproot Nao e PQ

O endereco Taproot (`tb1p`) expoe chave publica secp256k1 de 32 bytes no witness program (BIP 341). Isso e
definido no consenso Bitcoin e nao pode ser alterado pelo Kerosene. Uma maquina quantica criptograficamente
relevante poderia atacar o DLP e recuperar a chave privada.

**Consequencia:**
- ML-DSA no Intent + ML-KEM no transporte + FROST secp256k1 no Taproot
= comunicacao PQ, mas custodia on-chain ainda vulneravel

**O que PQ protege hoje:**
- Autorizacao de Intents
- Identidade dos vaults
- Mensagens de DKG wire
- Reshare distribuido
- Emissao e rotacao de roster
- Atualizacao de software e release manifests
- Auditoria (audit keys PQ)
- Envelopes de backup e transporte de shares
- Dados capturados hoje que continuariam sensiveis no futuro (harvest-now-decrypt-later)

**O que PQ nao protege hoje:**
- UTXOs Taproot on-chain (depende de evolucao do consenso Bitcoin, ex: BIP 360/P2MR)

---

## Design Decisions (Corrigidas)

### Separação de Chaves por Função

| Chave | Uso | Algoritmo | Threshold |
|---|---|---|---|
| FROST secp256k1 | Custodia e assinatura Bitcoin (Taproot) | Schnorr | 2/3 |
| ML-DSA-65 por vault | Identidade e autenticacao PQ do vault | ML-DSA-65 (FIPS 204) | Individual |
| Ed25519 por vault | Identidade classica hibrida | Ed25519 | Individual |
| ML-KEM-768 | Estabelecimento de segredo PQ | ML-KEM-768 (FIPS 203) | Chave do receptor por key epoch; encapsulamento novo por mensagem |
| X25519 | Estabelecimento classico hibrido | X25519 | Chave do receptor por transport epoch; chave do remetente efemera por envelope |
| AES-256 / ChaCha20 | Protecao simetrica | AES-256-GCM / ChaCha20-Poly1305 | N/A |
| TPM/TEE | Protecao das seeds locais | Platform-specific | N/A |

ML-DSA-65 NAO substitui FROST. Nao fornece DKG threshold, shares t-de-n, agregacao Taproot, endereco Bitcoin,
nem assinatura reconhecida por miners.

### Separacao de Autoridades

| Conjunto | Responsabilidade | Nao pode |
|---|---|---|
| `VaultRoster` | DKG, reshare e shares FROST | Emitir Intent ou alterar constitution |
| `SettlementAuthorities` | Autorizar Intents hibridos | Participar como peer FROST por esse papel |
| `GovernanceAuthorities` | Alterar roster, suites e constitution | Assinar transacao diretamente |
| `ReleaseAuthorities` | Aprovar binarios e manifests | Autorizar settlement |

As chaves do KFE pertencem a `SettlementAuthorities`, nunca ao `VaultRoster`. Rotacao de authority exige
governance independente, key epoch monotonic e cadeia auditavel. As chaves privadas Ed25519 e ML-DSA do
KFE devem ficar em signer dedicado, HSM/TPM ou processos isolados; nao no mesmo processo que recebe trafego
publico e acessa o ledger.

### Envelope Hibrido Canonico

```
ss_classical = X25519(sender_eph_sk, receiver_x25519_pk)
(ct_pq, ss_pq) = ML-KEM-768.Encapsulate(receiver_kem_pk)

ikm = len(ss_classical) || ss_classical || len(ss_pq) || ss_pq
prk = HKDF-SHA-384-Extract(kdf_salt, ikm)

context = deterministic_encode(
    domain_separator,       // "KEROSENE-VAULT-MESH-HYBRID-V1"
    transcript_hash,        // SHA-384 do contexto da sessao
    suite_id,               // "hybrid-x25519-mlkem768-aes256gcm"
    sender_id,
    receiver_id,
    epoch
)

aead_key = HKDF-SHA-384-Expand(prk, "aead-key" || context, 32)
confirmation_key = HKDF-SHA-384-Expand(prk, "confirmation" || context, 32)

ciphertext = AES-256-GCM(aead_key, nonce, plaintext, authenticated_header)
```

Propriedades:
- Seguro enquanto X25519 OU ML-KEM-768 permanecer seguro
- HKDF-Extract combina secrets com encoding length-prefixed; HKDF-Expand separa chaves por finalidade
- Transcript hash vincula envelope ao contexto (anti-replay cross-session)
- AAD autentica metadados sem criptografa-los
- Rejeitar X25519 shared secret all-zero, falha de confirmacao/AEAD apos ML-KEM, nonce repetido e chave expirada
- Esta construcao deve ter especificacao testavel e revisao criptografica externa antes de producao

### Assinatura Hibrida: AND, Nao OR

```
valido = Ed25519_verify(msg, ed_pk) AND ML-DSA-65_verify(msg, ml_dsa_pk)
```

O conteudo assinado por ambos:

```
canonical_hash = SHA-384(deterministic_encode(
    protocol_version        // 2
    || message_type
    || suite_id
    || sender_id
    || receiver_id
    || roster_hash
    || constitution_hash
    || epoch
    || sequence
    || expires_at
    || payload_hash
    || ed25519_key_id
    || ml_dsa_key_id
))
```

Ambas as assinaturas cobrem o mesmo `canonical_hash`. A assinatura Ed25519 tambem cobre o `ml_dsa_key_id`,
e a ML-DSA cobre o `ed25519_key_id` — anti-stripping bidirecional.
`deterministic_encode` deve ser definido por formato canonico (CBOR deterministico ou estrutura binaria
length-prefixed); concatenacao textual ou JSON nao canonico sao proibidos.

### crypto_suite_id por Artefato, Nao Global

Cada artefato persistido registra sua propria suite:

```
Envelope {
    format_version: u16,
    suite_id: String,          // "hybrid-x25519-mlkem768-aes256gcm"
    key_epoch: DayEpoch,
    sender_key_id: KeyId,
    recipient_key_id: KeyId,
    sender_x25519_ephemeral_public: [u8; 32],
    recipient_ml_kem_key_id: KeyId,
    ml_kem_ciphertext: Vec<u8>,
    kdf_salt: [u8; 48],
    nonce: [u8; 12],
    authenticated_header: Vec<u8>,
    transcript_hash: [u8; 48],
    ciphertext: Vec<u8>,
    classical_signature: Vec<u8>,
    pq_signature: Vec<u8>,
}
```

Aplica-se a: shares selados, DKG transcripts, reshare transcripts, Intents, receipts, audit records,
release manifests, certificados, backups.

Trocar `current_suite_id` global nao migra automaticamente dados antigos.

### suite_not_weaker: Capacidades Minimas, Nao String

```yaml
minimum_policy:
  pq_kem_security_category: 3        # NIST category >= 3
  pq_signature_security_category: 3  # NIST category >= 3
  symmetric_key_bits: 256
  minimum_quantum_work_factor_bits: 128
  hybrid_kem_required: true
  hybrid_signature_required: true
  downgrade_protection: true
```

A constitution autoriza suites completas, identificadas por hash da especificacao e versao de implementacao.
Algoritmo/parametros pertencem a suite; crate, versao, source hash, lockfile, SBOM e provenance pertencem
ao release manifest. Atualizacao corretiva de biblioteca nao deve exigir redefinir a forca da suite.

### Fallback: Nunca. Fail-Closed Sempre.

Se PQ e obrigatorio:
- Suite requerida indisponivel → recusar boot
- Assinatura PQ ausente → rejeitar mensagem
- Ciphertext PQ ausente → rejeitar envelope
- Suite desconhecida → rejeitar
- Downgrade → rejeitar

Perfil classico-only de laboratorio:
- Identificador de protocolo diferente (`"classical-only-lab-v1"`)
- Certificados diferentes
- Dados separados
- Impossibilidade de conexao com producao
- Compilacao incompativel com `--features production`

### Protecao Harvest-Now-Decrypt-Later

Mensagens sensiveis de DKG/reshare tem envelope hibrido na camada de aplicacao, mesmo dentro de mTLS:

```
mTLS classico (TLS 1.3)
  └── envelope X25519 + ML-KEM-768 (aplicacao)
        └── mensagem DKG/reshare autenticada
```

Assim, a seguranca nao depende de o stack TLS oferecer handshake hibrido nativo.

---

## TIER 0 — MODELO E FORMATOS (Fundacao)

Definir antes de qualquer implementacao. Congelar formatos, envelopes, e protocolo hibrido.

---

### Item 0.1: Definicao de Ameaca Quantica e Objetivos PQ

**Problema:** Sem definicao explicita do que PQ protege e do que nao protege. Escopo difuso leva a implementacao incompleta.

**Caminho:**
- NOVO: `docs/security/QUANTUM_THREAT_MODEL.md` — modelo de ameaca quantico

**O que fazer:**
1. Documentar:
   - Adversario: captura passiva hoje (harvest-now-decrypt-later) + ataque ativo futuro com CRQC
   - Ativos protegidos: shares, DKG transcripts, reshare messages, backups, identities, audit logs
   - Ativos NAO protegidos: UTXOs Taproot on-chain (limitacao do consenso Bitcoin)
   - Janela de risco: dados capturados hoje devem resistir a ataque quantico futuro
   - NIST security categories alvo: 3 para KEM, 3 para signatures
2. Separar claramente: custodia Bitcoin (FROST/secp256k1) vs identidade/transporte PQ (ML-KEM/ML-DSA)

**Foco:**
- **Seguranca:** Escopo claro evita falsa sensacao de protecao. Documentar o que PQ NAO cobre e tao importante quanto o que cobre.
- **Clean Code:** Documento referencia para todos os itens subsequentes.

---

### Item 0.2: Separacao de Custodia Bitcoin e Identidade/Transporte PQ

**Problema:** Plano anterior misturava FROST e ML-DSA como se fossem intercambiaveis. Nao sao.

**Caminho:**
- ALTERAR: `VAULT_MESH_PLAN.md` §12 — adicionar secao de separacao de chaves
- NOVO: `backend/kerosene-vault/docs/PQ_KEY_ARCHITECTURE.md`

**O que fazer:**
1. Definir key tree:
   - `custody/`: FROST secp256k1 (Bitcoin) — nao muda
   - `identity/`: Ed25519 + ML-DSA-65 (vault identity)
   - `transport/`: X25519 + ML-KEM-768 (KEM efemero + estatico)
   - `audit/`: Ed25519 + ML-DSA-65 (audit keys)
2. Cada dominio tem ciclo de vida independente
3. Rotacao de identity keys nao afeta custody keys
4. Compromisso de transport key nao compromete custody

**Foco:**
- **Seguranca:** Isolamento estrito entre dominios. Compromisso de um dominio nao propaga.
- **Clean Code:** KeyStore com namespaces (`custody/`, `identity/`, `transport/`, `audit/`).

---

### Item 0.3: Envelope Hibrido Canonico (X25519 + ML-KEM-768)

**Problema:** Plano anterior usava secp256k1 para criptografia (incorreto) e nao definia formato de envelope.

**Caminho:**
- NOVO: `backend/kerosene-vault/src/adapters/hybrid_envelope.rs` — implementacao do envelope
- NOVO: `backend/kerosene-vault/src/domain/hybrid_envelope.rs` — tipos de dominio
- ALTERAR: `backend/kerosene-vault/src/application/ports.rs` — `HybridEnvelopePort`
- ALTERAR: `backend/kerosene-vault/Cargo.toml` — crates `x25519-dalek`, `ml-kem`, `hkdf`, `sha3`

**O que fazer:**
1. Implementar `HybridEnvelope`:
   - `seal(plaintext, receiver_x25519_pk, receiver_kem_pk, context) -> Envelope`
   - `open(envelope, receiver_x25519_sk, receiver_kem_sk, context) -> Result<Vec<u8>>`
2. Contexto: `HybridContext { domain_separator, transcript_hash, suite_id, sender_id, receiver_id, epoch }`
3. Validar: format_version, suite_id conhecido, key_epoch nao expirado, signatures (Ed25519 + ML-DSA-65)
4. Envelope inclui sender X25519 ephemeral public key, ML-KEM ciphertext, KDF salt, AAD e transcript hash
5. Rejeitar: suite desconhecida, assinatura ausente, ciphertext truncado, nonce reuse, X25519 all-zero,
   falha de ML-KEM, chave expirada e key-id fora do roster/authority set
6. Serializacao canonica e length-prefixed; JSON nao canonico e proibido no transcript
7. Derivar chaves separadas por finalidade com HKDF-Extract/Expand
8. Definir RNG/DRBG e falha de entropia, zeroizacao, no-core-dump/no-swap, constant-time, limites antes
   de alocacao, KAT no boot, fuzzing, pin de dependencias, SBOM e provenance
9. Testes KAT: vetores oficiais e vetores deterministicos de integracao com seeds conhecidas

**Foco:**
- **Seguranca:** HKDF como combinador (nao concatenacao simples). Transcript hash bind. Nonce unico por envelope. AEAD autentica header. Zeroize de secrets apos uso.
- **Clean Code:** `HybridEnvelope` como tipo rico com serde. Builder pattern para construcao. Validacao no `open()`.
- **Testabilidade:** KAT vectors. Round-trip seal/open. Tamper detection (alterar ciphertext, signature, header).

---

### Item 0.4: Ciclo de Chaves Classicas e PQ

**Problema:** Sem definicao de como chaves classicas e PQ nascem, rotacionam e expiram juntas.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/domain/reshare_policy.rs` — adicionar `KeyLifecycle`
- NOVO: `backend/kerosene-vault/src/application/key_lifecycle.rs`
- ALTERAR: `backend/kerosene-vault/src/bootstrap/config.rs` — `VAULT_KEY_LIFECYCLE_*`

**O que fazer:**
1. Definir `KeyLifecycle`:
   - Genesis: gerar Ed25519 + ML-DSA-65 + X25519 receptor + ML-KEM-768; registrar public keys no roster/authority set
   - Rotacao de identity: a cada N epochs ou sob compromisso
   - Rotacao de transport: X25519 receptor e ML-KEM keypair por transport/key epoch; X25519 remetente
     efemero e novo encapsulamento ML-KEM aleatorio por envelope
   - Revogacao: identity key comprometida → quorum mesh revoga e substitui
2. Cada chave tem:
   - `created_at`: epoch de criacao
   - `expires_at`: epoch de expiracao (opcional)
   - `revoked_at`: epoch de revogacao (opcional)
   - `parent_key_id`: chave que autorizou a criacao
3. Rotacao atomica: identity keys classicas e PQ rotacionam juntas (bind)

**Foco:**
- **Seguranca:** Rotacao atomica evita janela onde so uma das chaves foi rotacionada. Revogacao requer quorum. Chaves expiradas recusadas em verify.
- **Clean Code:** `KeyLifecycle` como state machine. Eventos: Created, Rotated, Expired, Revoked.

---

### Item 0.5: Anti-Downgrade e Rollback Protection

**Problema:** Plano anterior propunha "fallback com warning" — inseguro. Precisa de fail-closed estrito.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/domain/constitution.rs` — `DowngradePolicy`
- ALTERAR: `backend/kerosene-vault/src/bootstrap/config.rs` — validacao de downgrade no boot

**O que fazer:**
1. `DowngradePolicy`:
   - `minimum_suite`: suite minima aceita (capability-based)
   - `require_hybrid`: se true, rejeita classical-only
   - `require_pq_signatures`: se true, rejeita mensagens sem ML-DSA
   - `require_pq_kem`: se true, rejeita envelopes sem ML-KEM
2. Validacao no boot: `VAULT_MINIMUM_SUITE` vs constitution `current_suite`
3. Validacao por mensagem: envelope `suite_id` vs `minimum_suite`
4. Rollback protection: `epoch` monotonicamente crescente. Rejeitar epoch < ultimo epoch visto.
5. Constitution rollback: hash da constitution anterior registrado. Rejeitar volta a versao antiga.

**Foco:**
- **Seguranca:** Fail-closed em todo downgrade. Epoch monotonic. Constitution hash chain. Suite validation por capacidade, nao string.
- **Clean Code:** `DowngradePolicy` como tipo rico, nao booleanos soltos. Validacao centralizada no envelope `open()`.

---

### Item 0.6: Estrategia de Migracao On-Chain (Quantum Migration Controller)

**Problema:** Endereco Taproot omnibus estavel e vulneravel a ataque quantico. Sem estrategia de saida dos fundos.

**Caminho:**
- NOVO: `backend/kerosene-vault/src/application/quantum_migration.rs` — QuantumMigrationController
- NOVO: `backend/kerosene-vault/src/domain/quantum_state.rs` — estados de migracao
- ALTERAR: `backend/kerosene-vault/src/domain/constitution.rs` — `quantum_migration` config

**O que fazer:**
1. Definir estados de migracao:

```
Q0 NORMAL              — operacao normal, sem ameaca detectada
Q1 PQ_PREPARED         — envelopes hibridos ativos, planos de migracao prontos
Q2 ELEVATED_RISK       — ameaca detectada, reduzir limites de permanencia
Q3 DEPOSITS_DISABLED   — bloquear novos depositos no endereco Taproot antigo
Q4 MIGRATION_ACTIVE    — iniciar sweep de fundos para destinos seguros
Q5 EMERGENCY_SWEEP     — sweep total, ignora caps, prioridade maxima de fee
Q6 MIGRATION_COMPLETE  — inventario reconciliado, fundos confirmados no destino
```

2. `QuantumMigrationController`:
   - Inventario de todos os UTXOs (id, valor, idade, script type, pubkey exposta)
   - Destino de migracao aprovado e atualmente valido pelo consenso Bitcoin
   - Templates de PSBT nao assinados, descriptors de emergencia e fee strategy atualizavel
   - Capacidade de varrer buckets (USERS, CHANNELS)
   - Constitution especial de emergencia sem reduzir threshold ou autenticacao
   - Migration drill periodico (testa sweep em testnet)
3. Transicao entre estados:
   - Q0 → Q1: decisao de governance (quorum mesh)
   - Q1 → Q2: deteccao externa autenticada (CVEs, anuncios de fornecedores e inteligencia de ameacas)
   - Q2 → Q3: risco confirmado; bloquear novos depositos antes do sweep
   - Q3 → Q4: iniciar migracao apos autorizacao de governance
   - Q4 → Q5: emergencia com o mesmo threshold e autorizacao reforcada
   - Q5 → Q6: inventario reconciliado e migracao confirmada
4. Impedir novos depositos em Q3+:
   - `GET /v1/bitcoin/deposit` retorna 409 com `quantum_state`
   - KFE notifica usuarios para nao depositar

**Foco:**
- **Seguranca:** Estados progressivos. Bloquear depositos antes do sweep. Drills usam templates nao assinados. Emergencia nunca reduz threshold, autenticacao ou validacao; bypass de caps exige autorizacao mais forte.
- **Clean Code:** State machine com transicoes documentadas. Cada transicao requer quorum mesh. Inventario de UTXOs com snapshot.
- **Urgencia:** Definir estados antes do go-live. Endereco omnibus estavel sem plano de saida e risco nao mitigado.

---

### Item 0.7: Versionamento e Compatibilidade de Formatos

**Problema:** Intents, envelopes, shares e certificados nao tem `format_version`. Upgrade futuro quebra compatibilidade.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/domain/constitution.rs` — `format_versions`
- ALTERAR: `backend/kerosene-vault/src/domain/intent_bind.rs` — adicionar `format_version`
- ALTERAR: `backend/kerosene-vault/src/adapters/share_aead.rs` — versionar share envelope
- ALTERAR: `backend/kerosene-vault/src/adapters/http.rs` — `X-Protocol-Version` header

**O que fazer:**
1. Adicionar `format_version: u16` em:
   - `Intent` (KFE → vault)
   - `Receipt` (vault → KFE)
   - Share envelope (disco)
   - DKG transcript
   - Reshare transcript
   - Certificate (mTLS)
   - Audit record
2. Negociacao de versao:
   - Cliente envia `X-Protocol-Version: 2`
   - Servidor responde com versao suportada ou 426 Upgrade Required
3. Regras de compatibilidade:
   - `format_version` desconhecido → rejeitar
   - `format_version` menor que minimo → rejeitar
   - Campos desconhecidos no core assinado → rejeitar
   - Extensoes somente em mapa `extensions` assinado, namespaced e com politica explicita de criticalidade

**Foco:**
- **Seguranca:** Formatos versionados impedem parsing ambiguity. Rejeitar versoes desconhecidas (fail-closed).
- **Clean Code:** Versao como campo obrigatorio em todo wire format. Serde com `#[serde(tag = "format_version")]`.
- **Compatibilidade:** Lab e prod podem usar versoes diferentes durante transicao. Negociacao explicita.

---

## TIER 1 — BLOQUEADORES CRIPTOGRAFICOS

Implementacao do envelope hibrido, identidade hibrida, reshare wire, e validacao independente.

---

### Item 1.1: Validacao Independente de PSBT em Cada Vault

**Problema:** PSBT policy validation existe mas e executada pelo coordinator. Cada vault deve validar independentemente antes de liberar share de assinatura.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/frost_wire_cosign.rs` — validacao pre-sign
- ALTERAR: `backend/kerosene-vault/src/domain/psbt_policy.rs` — `validate_independent()`

**O que fazer:**
1. Antes de `sign_share()`, cada vault executa:
   - Recebe `SignedIntent` + PSBT completo + input index + policy/epoch/roster hashes
   - Verifica Ed25519 AND ML-DSA-65 do KFE contra `SettlementAuthorities`
   - PSBT parse e verify (sem confiar no coordinator)
   - Policy check: fee cap, locktime, RBF, output bind, destination allowlist
   - Intent bind: outputs do PSBT batem com outputs do Intent
   - Confere prevouts/UTXOs, bucket, Taproot output key e sighash type
   - Recalcula localmente o sighash do input e compara com o FROST signing package
   - Anti-nonce: session_id nao usado neste vault
2. Se qualquer check falhar, vault recusa sign_share — nao apenas loga
3. Coordinator agrega somente quando obtiver `t` shares validos do roster autorizado
4. Alterar `TrCommitRequest`/`TrSignShareRequest` para vincular o hash canonico da proposta completa,
   nunca apenas um sighash fornecido pelo coordinator

**Foco:**
- **Seguranca:** Nao confiar em coordinator para validacao de PSBT. Cada vault e independente. Fail-closed se qualquer vault rejeitar.
- **Clean Code:** `validate_independent()` como metodo separado de `validate_for_coordinator()`. Testes com PSBT malicioso.

---

### Item 1.2: Intent com Assinatura Hibrida (Ed25519 + ML-DSA-65)

**Problema:** Intent atual nao tem assinatura PQ. KFE assina Intent com HMAC (Java quorum legado).

**Caminho:**
- ALTERAR: `backend/kerosene/kerosene-contracts/.../VaultMeshIntent.java` — adicionar campos PQ
- ALTERAR: `backend/kerosene-vault/src/domain/intent_bind.rs` — `IntentSignature` com dual sig
- ALTERAR: `backend/kerosene-vault/src/adapters/http.rs` — validar signatures no intent gate
- NOVO: `backend/kerosene/kfe-service/.../KfeVaultMeshIntentSigner.java` — assinar com Ed25519 + ML-DSA

**O que fazer:**
1. `IntentSignature`:
   - `ed25519_signature: [u8; 64]`
   - `ml_dsa65_signature: Vec<u8>` (ML-DSA-65 signature, ~3300 bytes)
   - `ed25519_key_id: KeyId`
   - `ml_dsa_key_id: KeyId`
   - `canonical_hash: [u8; 48]` (SHA-384 do intent canonico — ambas assinam o mesmo hash)
2. Validacao no vault:
   ```
   valido = ed25519_verify(canonical_hash, sig, pk)
         AND ml_dsa65_verify(canonical_hash, sig, pk)
   ```
   Se qualquer uma falhar → 401 Unauthorized
3. KFE gera assinatura hibrida ao criar Intent
4. Chaves do KFE registradas em `SettlementAuthorities`, separadas do `VaultRoster`
5. Rotacao de `SettlementAuthorities` exige governance independente e mantem cadeia de key epochs
6. `KfeVaultMeshIntentSigner` usa signer dedicado/HSM/TPM ou duas fronteiras isoladas; as duas chaves
   privadas nao ficam diretamente no processo principal do KFE

**Foco:**
- **Seguranca:** AND, nao OR. Ambas as assinaturas cobrem o mesmo hash canonico. Anti-stripping: cada assinatura referencia a key_id da outra. Rejeitar se qualquer assinatura ausente.
- **Clean Code:** `IntentSignature` como tipo de dominio. Validacao em `IntentBindPort::verify_signatures()`.
- **Performance:** Definir benchmark reproduzivel no hardware minimo suportado e limite p95; nao fixar
  latencia teorica no protocolo.

---

### Item 1.3: Identidade Hibrida dos Vaults (Ed25519 + ML-DSA-65)

**Problema:** Vaults se identificam por `VAULT_NODE_ID` (string). Sem chave criptografica de identidade. mTLS usa certs efemeros de lab.

**Caminho:**
- NOVO: `backend/kerosene-vault/src/adapters/identity_hybrid.rs` — HybridIdentity
- ALTERAR: `backend/kerosene-vault/src/domain/peer.rs` — `PeerIdentity` com chaves hibridas
- ALTERAR: `backend/kerosene-vault/src/adapters/auth_mtls.rs` — bind mTLS cert a identity key
- ALTERAR: `backend/kerosene-vault/src/bootstrap/wiring.rs` — gerar/carregar identity keys

**O que fazer:**
1. `HybridIdentity`:
   - `node_id: NodeId`
   - `ed25519_public: [u8; 32]`
   - `ml_dsa65_public: Vec<u8>`
   - `x25519_public: [u8; 32]`
   - `ml_kem768_public: Vec<u8>`
   - `created_at: DayEpoch`
   - `expires_at: Option<DayEpoch>`
2. Genesis: cada vault gera par de chaves identity (Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768)
3. Roster inclui `PeerIdentity` para cada vault
4. Autenticacao wire: mensagens DKG/reshare assinadas com Ed25519 + ML-DSA-65
5. mTLS cert fingerprint bind ao `ed25519_public` (SPIFFE SAN ou extension)

**Foco:**
- **Seguranca:** Chaves identity geradas no vault, nunca saem (so public keys no roster). mTLS cert bind a identity key previne impersonation mesmo se cert vazar.
- **Clean Code:** `HybridIdentity` como tipo de dominio. `IdentityStorePort` para persistencia segura.

---

### Item 1.4: Envelope Hibrido para DKG e Reshare Wire

**Problema:** Mensagens DKG wire (`dkg_wire.rs`) e reshare wire (a implementar) trafegam em HTTP/TLS sem envelope hibrido na camada de aplicacao. Vulneraveis a harvest-now-decrypt-later se TLS for quebrado no futuro.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/dkg_wire.rs` — envolver mensagens em HybridEnvelope
- ALTERAR: `backend/kerosene-vault/src/adapters/dkg_tr_wire.rs` — idem
- NOVO: `backend/kerosene-vault/src/adapters/reshare_wire.rs` — nascer com envelope hibrido
- ALTERAR: `backend/kerosene-vault/src/adapters/http.rs` — middleware de envelope

**O que fazer:**
1. Antes de enviar mensagem DKG wire:
   - Serializar `Round1WireMessage` como bytes
   - `HybridEnvelope::seal(bytes, peer_eph_pk, peer_kem_pk, context)`
   - Enviar envelope (nao plaintext)
2. Ao receber:
   - `HybridEnvelope::open(envelope, receiver_x25519_sk, receiver_kem_sk, context)`
   - Se falhar (suite, assinatura, KEM) → rejeitar mensagem
   - Deserializar payload
3. Contexto do envelope: `domain="dkg-wire", session_id, suite_id, sender, receiver, epoch`
4. Middleware HTTP: `HybridEnvelopeLayer` que automaticamente envelopa/desenvelopa mensagens DKG/reshare

**Foco:**
- **Seguranca:** Protege mensagens mesmo se TLS for quebrado. Transcript hash bind previne replay cross-session. AAD autentica metadados. Chaves efemeras por sessao DKG.
- **Clean Code:** Middleware layer em `http.rs` (Axum). Transparente para logica de DKG wire. Reusar `HybridEnvelope` do Item 0.3.
- **Performance:** Medir encapsulacao/decapsulacao no hardware minimo suportado e impor limites p95
  definidos por benchmark reproduzivel.

---

### Item 1.5: Reshare Sobre Wire (distributed_wire)

**Problema:** `refresh_tr_shares_in_process` (frost_tr_bitcoin.rs:216) exige TODOS os N key packages em memoria local. `PolicyReshareHook` recusa in-process. So funciona em `dealer_lab`. Sem wire reshare, rotacao diaria de shares em prod nao roda.

**Caminho:**
- NOVO: `backend/kerosene-vault/src/adapters/reshare_wire.rs` — WireReshareHub (espelho de WireDkgHub)
- NOVO: `backend/kerosene-vault/src/adapters/dkg_tr_wire_reshare.rs` — Taproot FROST wire reshare
- ALTERAR: `backend/kerosene-vault/src/adapters/frost_reshare.rs` — delegar para WireReshareHub
- ALTERAR: `backend/kerosene-vault/src/adapters/http.rs` — rotas `/v1/reshare/tr/round1`, `/v1/reshare/tr/round2`, `/v1/reshare/tr/finalize`
- ALTERAR: `backend/kerosene-vault/src/adapters/daily_rotation.rs` — hook chamar wire path

**O que fazer:**
1. `WireReshareHub` — protocolo 3-round com envelope hibrido:
   - Round1: cada vault gera `(round1_secret, round1_package)`, envelopa, envia aos peers
   - Round2: cada vault recebe packages, gera `round2_package`, envelopa, envia
   - Finalize: cada vault recebe round2, `refresh_dkg_shares`, persiste apenas seu share
2. Binding: SHA-384 sobre `session_id + day_epoch + roster_hash + constitution_hash + transcript` em cada envelope
3. Rejeitar: threshold drift, late-join, remocao de participante, VK drift (mesmo `tb1p`)
4. Cada vault persiste apenas seu share — nunca ve shares dos outros
5. Envelope hibrido (Item 1.4) em todas as mensagens wire
6. Testes: `reshare_wire_3_nodes`, `reshare_wire_vk_invariant`, `reshare_wire_reject_drift`, `reshare_wire_hybrid_envelope`

**Foco:**
- **Seguranca:** Envelope hibrido protege shares em transito. VK invariant assertion (deposit `tb1p` nunca muda). Fail-closed se peer rejeitar. Binding criptografico cross-round (SHA-384).
- **Clean Code:** API espelha `WireDkgHub`. Reusar `http_peer.rs` para fanout. Middleware de envelope hibrido transparente.
- **Testabilidade:** Port para mock de peer HTTP. KAT vectors para envelope hibrido + reshare.

---

### Item 1.6: Persistencia Versionada por Suite

**Problema:** Shares, DKG transcripts, e backups salvos em disco sem `format_version` ou `suite_id`. Upgrade de suite deixa dados antigos incompativeis sem migracao.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/share_aead.rs` — adicionar `format_version` + `suite_id` ao envelope de share
- ALTERAR: `backend/kerosene-vault/src/adapters/share_tpm.rs` — idem
- ALTERAR: `backend/kerosene-vault/src/adapters/share_tee.rs` — idem
- ALTERAR: `backend/kerosene-vault/src/adapters/session_persist.rs` — versionar session state
- NOVO: `backend/kerosene-vault/src/application/share_migration.rs` — migrar shares entre suites

**O que fazer:**
1. Envelope de share em disco:
   ```
   ShareEnvelope {
       format_version: u16,
       suite_id: String,
       share_id: String,
       node_id: NodeId,
       key_epoch: DayEpoch,
       share_kind: ShareKind,  // "frost-tr", "frost-intent"
       nonce: [u8; 12],
       ciphertext: Vec<u8>,     // ChaCha20-Poly1305 (AEAD disk) ou TPM-sealed
       aad_hash: [u8; 32],      // SHA-256 do AAD bind
   }
   ```
2. `ShareMigrationPort`:
   - Detecta share com `suite_id` antigo
   - Deselar com suite antiga
   - Re-selar com suite nova
   - Atomico: soh apaga antigo apos novo persistido + verificado
3. Migracao disparada por day-advance ou manual
4. Backup de share antigo antes de migrar

**Foco:**
- **Seguranca:** Migracao atomica (nunca fica sem share em disco). Backup pre-migracao. AAD bind share_id + node_id (anti-swap). Suite_id imutavel no envelope.
- **Clean Code:** `ShareEnvelope` como struct versionada. `ShareMigrationPort` trait. Migracao idempotente.

---

### Item 1.7: CI com Production + PQ Obrigatorio

**Problema:** CI atual (`github-actions.yml`) nao builda vault com `--features production`. Nao executa `cargo test` no vault. Nao verifica PQ.

**Caminho:**
- NOVO: `.github/workflows/vault-ci.yml` — workflow dedicado ao vault
- ALTERAR: `.github/workflows/github-actions.yml` — adicionar job vault (ou link)

**O que fazer:**
1. Job `vault` com matrix:
   - `features: ["", "production"]`
   - `crypto: ["classical-lab", "hybrid"]`
2. Passos:
   - `cargo check --features production,hybrid --no-default-features`
   - `cargo test --features production,hybrid`
   - `cargo clippy --features production,hybrid -- -D warnings`
   - `cargo audit` (dependency scan)
   - KAT tests: ML-KEM-768, ML-DSA-65 (vetores NIST oficiais)
3. Validar:
   - `dealer_lab` nao compila com `--features production`
   - `static_token` nao compila com `--features production`
   - `ATTESTATION_MODE=sim` nao aceito com `--features production`
   - Hybrid envelope requer ambas as assinaturas (teste de stripping falha CI)
   - Classical-only lab nao conecta com hybrid prod (protocol version mismatch)
4. Build imagem Docker com `--features production,hybrid` e push

**Foco:**
- **Seguranca:** CI falha se PQ ausente em production. CI falha se fallback classical-only existir. KAT vectors garantem implementacao correta.
- **Clean Code:** Workflow separado para vault. Cache agressivo de `target/` e `~/.cargo`.
- **Fail-fast:** Matrix strategy isolada.

---

### Item 1.8: Testes de Stripping, Downgrade e Rollback

**Problema:** Plano anterior nao tinha testes adversariais para ataques de downgrade PQ.

**Caminho:**
- NOVO: `backend/kerosene-vault/tests/pq_adversarial.rs` — testes adversariais
- NOVO: `backend/kerosene-vault/tests/hybrid_envelope_kat.rs` — KAT vectors
- NOVO: `backend/kerosene-vault/tests/migration_drill.rs` — migration drill tests

**O que fazer:**
Implementar no minimo estes testes adversariais:

1. **Stripping:** remover assinatura ML-DSA de Intent → rejeitado
2. **Stripping:** remover ciphertext ML-KEM de envelope → rejeitado
3. **Suite downgrade:** envelope com `suite_id="classical-only"` em contexto hybrid → rejeitado
4. **Key substitution:** trocar `ml_dsa_key_id` no Intent mantendo assinatura → rejeitado
5. **Replay cross-epoch:** envelope do epoch N reenviado no epoch N+1 → rejeitado
6. **Replay cross-vault:** envelope do vault-1 reenviado para vault-2 → rejeitado
7. **Downgrade classical-only:** forcar `require_pq=false` na config → boot recusado
8. **Ciphertext corruption:** alterar 1 byte do ciphertext ML-KEM → decapsula falha
9. **Signature over wrong transcript:** assinatura valida sobre payload diferente → rejeitado
10. **Cross-session mixing:** mesclar round1 do vault-1 com round2 do vault-2 em DKG → rejeitado
11. **Constitution rollback:** tentar carregar constitution antiga → rejeitado
12. **TPM counter rollback:** tentar usar sealed blob com counter antigo → rejeitado
13. **Seed corruption:** alterar seed file → boot recusado
14. **RNG failure detection:** mock RNG que retorna constantes → detectado
15. **ML-KEM KAT:** vetores oficiais NIST FIPS 203
16. **ML-DSA KAT:** vetores oficiais NIST FIPS 204
17. **Interop:** vault com suite v1 falando com vault suite v2 via upgrade path
18. **Envelope migration:** share selado com suite v1 migrado para suite v2
19. **DoS por mensagem PQ grande:** envelope > 100KB → rejeitado com rate-limit
20. **Zeroize:** secrets em memoria zerados apos drop (verificar com valgrind/miri)
21. **Partial rotation failure:** reshare falha no round2 → estado consistente, sem shares corrompidos
22. **Version mismatch:** vault atualizado falando com vault antigo → rejeitado com erro claro

**Foco:**
- **Seguranca:** Cobertura de todos os vetores de ataque de downgrade/stripping PQ. Testes automatizados no CI.
- **Clean Code:** Testes organizados por categoria (stripping, replay, downgrade, KAT, migration, DoS). Cada teste tem docstring explicando o vetor de ataque.
- **CI Integration:** Todos os testes rodam em CI com `--features production,hybrid`.

---

## TIER 2 — HARDWARE SECURITY

Protecao de seeds e shares em hardware real. Depende de HW fisico para teste.

---

### Item 2.1: TPM Seal com TSS Real

**Problema:** `share_tpm.rs:134` — stub. Share em claro no disco (AEAD). PC domestico vulneravel a host compromise.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/share_tpm.rs` — implementar TSS seal/unseal
- NOVO: `backend/kerosene-vault/src/adapters/share_tpm_tss.rs` — adapter TSS concreto
- ALTERAR: `backend/kerosene-vault/Cargo.toml` — crate `tss-esapi`
- ALTERAR: `backend/kerosene-vault/src/bootstrap/config.rs` — `--features tpm`

**O que fazer:**
1. Integrar `tss-esapi` com bindings ao `libtss2-esys`
2. `seal()`: selar share com PCR policy (PCR 0-7 measured boot) + auth value (Argon2id da passphrase)
3. `unseal()`: deselar com PCR validation + auth value
4. AAD bind: `share_id + node_id` no policy digest (anti-swap entre maquinas)
5. TPM AK para identity binding (provar que share so desela no mesmo hardware)
6. Fail-closed: se TPM ausente em producao → `FailClosed` (nunca `Mock`)
7. Selar seeds ML-KEM e ML-DSA no TPM (nao so shares FROST)
8. Testes: `tpm_seal_unseal`, `tpm_pcr_mismatch_reject`, `tpm_counter_rollback_reject`

**Foco:**
- **Seguranca:** PCR bind (measured boot). AAD anti-swap. Auth value Argon2id. TPM counter anti-rollback. Seeds PQ seladas no TPM.
- **Clean Code:** `TpmSealAdapter` implementa `ShareStorePort`. Modulo isolado. Mock em CI sem `/dev/tpm0`.
- **Portabilidade:** Abstrair chamadas TSS atras de trait.

---

### Item 2.2: Seeds ML-KEM/ML-DSA Seladas

**Problema:** Seeds PQ geradas mas armazenadas com mesma protecao de shares FROST. Precisam de protecao equivalente ou superior.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/identity_hybrid.rs` — selar seeds com ShareStorePort
- ALTERAR: `backend/kerosene-vault/src/adapters/share_aead.rs` — suportar `SeedKind::MlKem`, `SeedKind::MlDsa`
- ALTERAR: `backend/kerosene-vault/src/adapters/share_tpm.rs` — idem

**O que fazer:**
1. Seeds PQ seladas com mesmo mecanismo de shares FROST:
   - AEAD disk (Argon2id + ChaCha20-Poly1305) no lab
   - TPM seal em producao domestica
   - TEE seal em producao SEV/SGX
2. `SeedKind` enum: `FrostTr`, `FrostIntent`, `Ed25519`, `MlDsa65`, `X25519`, `MlKem768`
3. Cada seed tem `share_id` unico (ex: `identity/ed25519/vault-1`)
4. AAD bind: `seed_id + node_id + key_epoch`

**Foco:**
- **Seguranca:** Seeds PQ com mesma protecao de shares FROST. AAD anti-swap. Rotacao de seeds gera novo `share_id`.
- **Clean Code:** `SeedKind` enum. `ShareStorePort` generico para seeds e shares.

---

### Item 2.3: Secure Boot + PCR Policy para Vault

**Problema:** Sem verificacao de integridade do binario do vault no boot. TPM PCR policy existe mas nao ha configuracao de Secure Boot.

**Caminho:**
- NOVO: `docs/ops/SECURE_BOOT_VAULT.md` — procedimento de secure boot
- ALTERAR: `backend/kerosene-vault/src/bootstrap/config.rs` — `VAULT_SECURE_BOOT_PCR_POLICY`

**O que fazer:**
1. Documentar PCR policy esperada:
   - PCR 0: firmware
   - PCR 1: firmware config
   - PCR 2: external ROMs
   - PCR 3: external ROM config
   - PCR 4: bootloader (GRUB/systemd-boot)
   - PCR 5: bootloader config
   - PCR 7: secure boot state + keys
2. Vault no boot verifica PCR values contra expected policy
3. Se PCR mismatch → boot recusado (possivel compromisso de firmware/bootloader)
4. Script de medicao: `scripts/vault/measure_pcr_policy.sh`

**Foco:**
- **Seguranca:** PCR policy previne boot de binario alterado. Fail-closed se PCR mismatch.
- **Operacao:** Documentar procedimento de atualizacao (update de kernel requer recalculo de PCR policy).

---

### Item 2.4: SEV/SGX Quote HW (VCEK Chain + DCAP)

**Problema:** `sev_snp.rs:41` e `sgx.rs` sao fail-closed sem HW. Com `--features tee_hw`, sem chain VCEK completa.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/attestation_tee/sev_snp.rs` — VCEK chain fetch + verify
- ALTERAR: `backend/kerosene-vault/src/adapters/attestation_tee/sgx.rs` — DCAP quote generation + verify
- ALTERAR: `backend/kerosene-vault/src/adapters/attestation_tee/quote.rs` — unificar quote verification
- ALTERAR: `backend/kerosene-vault/Cargo.toml` — crates VCEK/DCAP

**O que fazer:**
1. SEV-SNP: fetch VCEK chain da AMD KDS, validar ARK → ASK → VCEK, REPORT_DATA bind
2. SGX: DCAP quote via `sgx_dcap_quoteverify_rs`, validar contra Intel PCS, MRENCLAVE + MRSIGNER
3. `TeeAttestationPort` unificado para SEV e SGX
4. Testes com HW real

**Foco:**
- **Seguranca:** VCEK chain completa. REPORT_DATA bind (SHA-384 da constitution + measurement). TCB version check.
- **Clean Code:** `TeeAttestationPort` trait. Feature flags `sev` e `sgx` independentes.

---

### Item 2.5: Protecao Contra Clonagem e Rollback de TPM/TEE

**Problema:** TPM counter e SEV/SGX TCB version podem sofrer rollback. Sem deteccao.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/share_tpm.rs` — counter validation
- ALTERAR: `backend/kerosene-vault/src/adapters/attestation_tee/sev_snp.rs` — TCB version check
- ALTERAR: `backend/kerosene-vault/src/adapters/attestation_tee/sgx.rs` — TCB version check

**O que fazer:**
1. TPM: usar `TPM2_NV_Counter` monotonic. Sealed blob inclui counter value. Unseal verifica counter atual >= counter do blob. Se menor → rollback detectado.
2. SEV-SNP: verificar `reported_tcb.boot_loader`, `reported_tcb.tee`, `reported_tcb.snp` contra `committed_tcb`. Se menor → firmware antigo.
3. SGX: verificar `cpu_svn` contra versao minima conhecida.
4. Se rollback detectado → boot recusado, shares nao deselados.

**Foco:**
- **Seguranca:** Monotonic counters. TCB version minima configurada na constitution. Fail-closed em rollback.
- **Clean Code:** Validacao de counter/TCB em `ShareStorePort::get_share()` antes de deselar.

---

## TIER 3 — OPERACAO

Deploy, observabilidade, scripts, e testes E2E.

---

### Item 3.1: K8s Deploy Cobre Vault Mesh (Pods)

**Problema:** Vaults sobem via Docker Compose no host. K8s `deploy.sh` nao tem vault resources.

**Caminho:**
- NOVO: `infra/kubernetes/base/vault-deployment.yaml`
- NOVO: `infra/kubernetes/base/vault-service.yaml`
- NOVO: `infra/kubernetes/overlays/staging/vault-1-deployment.yaml`
- NOVO: `infra/kubernetes/overlays/staging/vault-2-deployment.yaml`
- NOVO: `infra/kubernetes/overlays/staging/vault-3-deployment.yaml`
- NOVO: `infra/kubernetes/overlays/staging/vault-services.yaml`
- NOVO: `infra/kubernetes/overlays/staging/vault-network-policy.yaml`
- ALTERAR: `infra/kubernetes/scripts/deploy.sh`

**O que fazer:**
1. Deployment base: init container (mTLS cert), vault container (`--features production,hybrid`), PV para `$VAULT_DATA_DIR`, probes liveness/readiness
2. Overlays: staging vault-1/2/3 com mTLS, Tor, `VAULT_RESHARE_POLICY=daily`
3. NetworkPolicy: KFE → vault-1:7801; vault↔vault:7800
4. Secrets: mTLS certs, Tor keys, identity seeds (gerados em ceremony)

**Foco:**
- **Seguranca:** Secrets em Kubernetes Secret. NetworkPolicy restritiva. Init container nao deixa secret em camada.
- **Clean Code:** Kustomize base + overlays.

---

### Item 3.2: Scripts de Teste E2E Multi-Node

**Problema:** `lab_e2e.sh`, `lab_pentest.sh`, `lab_testnet3_smoke.sh` nao existem.

**Caminho:**
- NOVO: `scripts/lab_e2e.sh`
- NOVO: `scripts/lab_pentest.sh`
- NOVO: `scripts/lab_testnet3_smoke.sh`
- NOVO: `scripts/lib/vault_test_helpers.sh`

**O que fazer:**
1. `lab_e2e.sh`: DKG → sign → day-advance → reshare → verificar `tb1p` identico
2. `lab_pentest.sh`: anti-nonce replay, intent double-spend, PSBT bypass, DKG late-join, threshold drift + testes PQ (stripping, downgrade)
3. `lab_testnet3_smoke.sh`: testnet3 publica, `tb1p`, PSBT sign realista

**Foco:**
- **Seguranca:** Pentest cobre vetores PQ (stripping, downgrade, rollback) + vetores classicos.
- **CI:** Scripts via `docker compose` com profile lab. Output JUnit XML.

---

### Item 3.3: Observabilidade (Metrics + Dashboard + Alertas)

**Problema:** Sem metricas Prometheus ou dashboard. Health so `/v1/health/mesh`.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/adapters/http.rs` — `/v1/metrics`
- NOVO: `infra/kubernetes/base/vault-servicemonitor.yaml`
- NOVO: `infra/docker/grafana/dashboards/vault-mesh.json`
- ALTERAR: `backend/kerosene-vault/Cargo.toml` — crate `metrics`

**O que fazer:**
1. Metricas: health, signing rate/latency, reshare counter, day_epoch gauge, peer connectivity, intents, PSBT rejections, PQ signature verify latency, hybrid envelope operations
2. Dashboard: health, signing, mesh, intents, PQ operations
3. Alertas: vault down, reshare failed, day_epoch drift > 1, PQ suite mismatch

**Foco:**
- **Seguranca:** Endpoint protegido por mTLS. Nao expor secrets.
- **Observabilidade:** Metricas PQ (latencia de ML-DSA verify, ML-KEM decapsulate).

---

### Item 3.4: Revogacao e Rotacao de Certificados

**Problema:** Sem mecanismo de revogacao de identity keys ou mTLS certs.

**Caminho:**
- ALTERAR: `backend/kerosene-vault/src/application/key_lifecycle.rs` — `revoke_identity()`
- ALTERAR: `backend/kerosene-vault/src/adapters/http.rs` — `/v1/identity/revoke`
- NOVO: `scripts/vault/rotate_mtls_certs.sh`

**O que fazer:**
1. Revogacao de identity key:
   - Quorum mesh aprova revogacao
   - Chave marcada `revoked_at` no roster
   - Todos os vaults recusam mensagens assinadas pela chave revogada
   - Substituicao por nova identity key (re-DKG parcial ou admission de nova chave)
2. Rotacao de mTLS certs:
   - Script `rotate_mtls_certs.sh` gera novos certs com TTL curto
   - Vaults recarregam certs sem restart (hot-reload)
   - Cert antigo removido apos todos os vaults confirmarem novo

**Foco:**
- **Seguranca:** Revogacao requer quorum. CRL-like: lista de chaves revogadas no roster. mTLS cert rotation sem downtime.
- **Clean Code:** `RevocationList` como parte do roster.

---

### Item 3.5: Quantum Migration Drills

**Problema:** QuantumMigrationController (Item 0.6) precisa de testes periodicos de sweep.

**Caminho:**
- NOVO: `scripts/lab_quantum_drill.sh`
- NOVO: `backend/kerosene-vault/tests/migration_drill.rs`

**O que fazer:**
1. `lab_quantum_drill.sh`:
   - Sobe 3 vaults + regtest
   - Cria UTXOs de teste (depositos simulados)
   - Transiciona Q0 → Q1 → Q2 → Q3 → Q4 → Q5
   - Verifica que depositos sao bloqueados em Q4+
   - Executa sweep em Q5
   - Verifica que todos os UTXOs foram varridos
   - Report: tempo de sweep, fees gastos, UTXOs restantes (deve ser 0)
2. Drill periodico em staging (mensal)
3. Relatorio de drill com metricas

**Foco:**
- **Seguranca:** Drills validam que a migracao funciona. Sweep real em testnet antes de precisar em mainnet.
- **Operacao:** Procedimento documentado. Metrica de tempo de sweep (importante para janela de risco).

---

### Item 3.6: Tor Authorized Clients

**Problema:** Tor HS e v3 public onion. `authorized_clients` scaffolded mas vazio.

**Caminho:**
- ALTERAR: `infra/docker/compose/vault-mesh-tor.compose.yaml`
- ALTERAR: `infra/runtime/tor/entrypoint.sh`
- NOVO: `scripts/vault/gen_tor_auth_clients.sh`

**O que fazer:**
1. `gen_tor_auth_clients.sh`: gera pares X25519, formato `.auth`, output `<onion>.auth` + chave privada
2. `entrypoint.sh`: se `VAULT_TOR_AUTH_CLIENTS=true`, configurar `HiddenServiceAuthorizeClient stealth`
3. Distribuicao de chaves em ceremony

**Foco:**
- **Seguranca:** Stealth auth. Chaves geradas offline. Rotacao em ceremony.

---

### Item 3.7: Incident Response para Compromisso PQ

**Problema:** Sem procedimento para responder a avanco quantico (CRQC announcement, vulnerabilidade em ML-KEM/ML-DSA).

**Caminho:**
- NOVO: `docs/ops/INCIDENT_RESPONSE_PQ.md`

**O que fazer:**
1. Definir cenarios:
   - CRQC anunciado (maquina quantica criptograficamente relevante)
   - Vulnerabilidade em ML-KEM (breaking change no NIST standard)
   - Vulnerabilidade em ML-DSA (idem)
   - Vulnerabilidade em secp256k1 (ataque classico ou quantico)
2. Resposta por cenario:
   - CRQC: transicao imediata Q0 → Q2, preparar Q3 sweep
   - ML-KEM vuln: rotacionar para nova versao de ML-KEM ou algoritmo alternativo
   - ML-DSA vuln: rotacionar identity keys, revogar chaves antigas
   - secp256k1 vuln: Q5 EMERGENCY_SWEEP imediato
3. Canais de comunicacao: mailing list PGP, canal seguro out-of-band
4. Drill de incident response (simulado)

**Foco:**
- **Seguranca:** Procedimento documentado antes do go-live. Canais de comunicacao fora da infra Kerosene.
- **Operacao:** Drill periodico. Contatos de emergencia.

---

## TIER 4 — DECISOES DE PRODUTO

Itens que dependem de decisao de negocio, nao tecnica.

---

### Item 4.1: Profit Splits % CHANNELS / INFRA

Decidir percentuais com stakeholders. Constitution define `ProfitSplits` sem valores finais.

---

### Item 4.2: Miner Payout Frequency

Decidir frequencia (diario, semanal, por-epoch). Constitution define `payout_frequency`.

---

### Item 4.3: HashiCorp Vault Pos-Mesh

Decidir se mantem para secrets ops ou migra para Kubernetes Secrets / vault mesh.

---

### Item 4.4: Endereco Deposito USERS (Omnibus vs Rotacao)

Decidir entre omnibus estavel ou rotativo por usuario. Impacto em privacidade e estrategia de migracao quantica (omnibus estavel e pior para PQ).

**Nota PQ:** Endereco omnibus estavel por anos e risco quantico concentrado. Rotativo mitiga (UTXOs menores, mais faceis de varrer). Considerar na decisao.

---

### Item 4.5: Javadocs "F0 Stub"

Atualizar `VaultMeshIntent.java` e `VaultMeshReceipt.java`. Remover "stub". Baixo esforco.

---

### Item 4.6: Seating Policy Admission (Pos-Genesis)

`admission_seating()` para novos nos priorizando SEV > SGX > domestic.

---

### Item 4.7: CHANNELS → LND Inject (Implementacao Real)

`InjectGateway` atualmente retorna `refuse()`. Implementar logica real de abertura de canais Lightning.

---

## TIER 5 — QUICK WINS

---

### Item 5.1: panic! em Testes

`bucket_memory.rs:500`, `dkg_wire.rs:1013`. Substituir por assertions semanticas.

---

### Item 5.2: Staging Compose TLS Cert Gen Automatizado

Init container gera certs staging automaticamente. Remove passo manual.

---

### Item 5.3: Ceremony Checklist Script

`scripts/genesis_ceremony_checklist.sh` com verificacao de PQ keys e hybrid envelopes.

---

## Ordem de Execucao (PQ-First)

### Fase 0 — Especificacao PQ (Semanas 1-6)
0.1. Definicao de ameaca quantica
0.2. Separacao de chaves (custodia vs identidade)
0.3. Envelope hibrido canonico
0.4. Ciclo de chaves
0.5. Anti-downgrade e rollback
0.6. Quantum Migration Strategy
0.7. Versionamento de formatos

### Fase 1 — Implementacao Crypto (Semanas 7-16)
1.1. Validacao independente de PSBT
1.2. Intent com assinatura hibrida
1.3. Identidade hibrida dos vaults
1.4. Envelope hibrido para DKG/reshare
1.5. Reshare sobre wire
1.6. Persistencia versionada por suite
1.7. CI production + PQ obrigatorio
1.8. Testes adversariais PQ

### Fase 2 — Hardware (Semanas 17-24, depende de HW fisico)
2.1. TPM seal com TSS real
2.2. Seeds ML-KEM/ML-DSA seladas
2.3. Secure Boot + PCR policy
2.4. SEV/SGX quote HW
2.5. Protecao contra clonagem/rollback

### Fase 3 — Operacao (Semanas 25-32)
3.1. K8s deploy vault mesh
3.2. Scripts E2E + pentest
3.3. Observabilidade (metrics/dashboards)
3.4. Revogacao e rotacao de certificados
3.5. Quantum migration drills
3.6. Tor authorized clients
3.7. Incident response PQ

### Fase 4 — Produto (Semanas 33+, paralelo)
4.1-4.7. Decisoes de produto

### Fase 5 — Quick Wins (a qualquer momento)
5.1-5.3. panic! testes, TLS cert gen, ceremony checklist

---

## Timeline Estimada

| Fase | Itens | Duracao | Bloqueia Go-Live? |
|---|---|---|---|
| 0 — Especificacao PQ | 7 | 4-6 semanas | Sim (fundacao) |
| 1 — Crypto | 8 | 6-10 semanas | Sim (protocolo) |
| 2 — Hardware | 5 | 4-8 semanas | Sim (seguranca operacional) |
| 3 — Operacao | 7 | 4-8 semanas | Sim (deploy + testes) |
| 4 — Produto | 7 | Continuo | Nao (decisoes) |
| 5 — Quick Wins | 3 | Intermitente | Nao |

**Total estimado para go-live (Fases 0-3): ~18-32 semanas**

Adicionar 4-8 semanas para auditoria externa de seguranca antes de fundos relevantes.

---

## Resumo das Correcoes (v1 → v2)

| Correcao | v1 | v2 |
|---|---|---|
| PQ priority | Tier 4 (futuro) | Tier 0 (fundacao) |
| Classical fallback | "warning" | Fail-closed, sem fallback |
| Hybrid encryption | secp256k1 (errado) | X25519 + ML-KEM-768 |
| Hybrid signature | OR implicito | AND explicito |
| crypto_suite_id | Global | Por artefato |
| suite_not_weaker | String ordenada | Capacidades minimas |
| Quantum migration | Inexistente | Item 0.6 (QuantumMigrationController) |
| DKG/reshare protection | So TLS | Envelope hibrido na camada de aplicacao |
| Timeline | 11-13 semanas | 18-32 semanas + auditoria |
| Adversarial tests | 6 cenarios | 22 cenarios (incluindo PQ) |
