# decmed-macaroon-auth

DecMed Macaroon caveat layer for fine-grained RME access control.

## Supported caveats

| Caveat | Example |
|--------|---------|
| `patient_address` | `patient_address = 0xPASIEN` |
| `related_rme_id` | `related_rme_id = RME-001` |
| `root_subject` | `root_subject = 0xDOKTER` |
| `delegated_by` / `delegated_to` | delegation chain pairs |
| `read_dataset_in` / `write_dataset_in` | `[LABORATORIUM]` |
| `read_function_in` / `write_function_in` | `[LABORATORIUM]` |
| `expires_before` | `2026-05-16T18:00:00` |
| `max_delegation_depth` | `1` |
| `proof_required` | `wallet_signature` |

`holder_address` is **not** used. Active identity is derived from `root_subject` and the
`delegated_by` / `delegated_to` chain (`active_subject` = last `delegated_to`, or `root_subject`).

## Effective access

Repeated whitelist caveats are intersected:

- `effective_read_dataset` = ∩ all `read_dataset_in`
- `effective_write_dataset` = ∩ all `write_dataset_in`
- `effective_read_function` = ∩ all `read_function_in`
- `effective_write_function` = ∩ all `write_function_in`
- `effective_expires_before` = earliest `expires_before`
- `effective_max_delegation_depth` = strictest (min) value; non-monotonic sequences are rejected

Missing whitelist for an operation → **DENY**.

## Initial token (Server PRE)

`issue_initial_token` signs with the PRE root key (from `MACAROON_ROOT_KEY`). Clients receive only the serialized macaroon.

Administrative grants issue separate read/write macaroons. The read token stays patient-scoped,
while the write token may carry `related_rme_id` to bind all writes and downstream clinical
delegations to one RME episode.

## Delegated token (client)

`attenuate_macaroon` appends caveats without the root key. Local checks reject expansions; PRE re-validates.

## PRE verification

1. Verify macaroon HMAC with root key.
2. Match `patient_address` / `related_rme_id`.
3. Validate delegation chain and `max_delegation_depth`.
4. If `proof_required = wallet_signature`, verify IOTA ED25519 signature over `WalletProofContext` JSON from `active_subject`.
5. Intersect caveats → allow READ/WRITE only when dataset + function categories match segment metadata.

## Segment metadata

Use `RmeSegmentMetadata` (`decmed-rme-segment`) fields: `segment_id`, `patient_address`, `related_rme_id`, `dataset_category`, `function_category`.
