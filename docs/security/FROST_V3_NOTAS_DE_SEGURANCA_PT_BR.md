# Notas de segurança da migração FROST v3

## O que esta mudança garante

Esta etapa corrige a integração do `vault-signer` com `frost-secp256k1` 3.x. Ela restaura compilação e testes, mas **não declara o Vault pronto para produção**.

As seguintes invariantes passam a ser verificadas explicitamente:

1. A mensagem e o conjunto exato de commitments formam um único `SigningPackage`. Cada share de assinatura fica vinculada a esse pacote.
2. A API do signer consome o pacote de nonces ao produzir uma share, impedindo reutilização acidental do mesmo valor pelo chamador.
3. A agregação rejeita conjuntos diferentes de participantes entre commitments e shares.
4. Uma sessão possui participantes únicos e imutáveis. Contribuições de participantes externos e duplicatas são rejeitadas.
5. O estado secreto da primeira rodada do DKG é consumido ao avançar, evitando reutilização acidental pela mesma máquina de estados.
6. A primeira rodada do DKG é tratada como broadcast autenticado. Na segunda rodada, cada pacote tem um destinatário específico e deve trafegar de forma confidencial.
7. Refresh preservando participantes e threshold usa o protocolo de refresh da biblioteca.
8. Mudanças de participantes ou threshold falham de forma fechada. O sistema não simula reshare com um novo DKG, pois isso alteraria silenciosamente a chave pública do grupo.
9. Geração por dealer permanece apenas para testes e laboratório.

## O que continua pendente

- Armazenamento durável e transacional de nonces de uso único entre processos, inclusive após crash, retry e failover.
- Broadcast consistente e autenticado entre máquinas diferentes para DKG.
- Canal confidencial, autenticado e ligado à identidade do destinatário para pacotes da rodada 2.
- Reshare distribuído para alterar membros ou threshold sem alterar a chave pública.
- Identidade de workload, autorização por SPIFFE ID, roster assinado e anti-replay replicado.
- Cerimônia de produção, attestation, auditoria externa e testes adversariais distribuídos.

## Regra operacional

Produção não pode habilitar dealer nem orquestração com todas as shares no mesmo processo. Os itens pendentes acima são bloqueadores de release e devem permanecer visíveis nas issues e no checklist de produção.
