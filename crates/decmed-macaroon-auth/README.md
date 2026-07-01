# decmed-macaroon-auth

DecMed Macaroon caveat layer for fine-grained RME access control.

## Compatibility facade

Consumers that still need low-level macaroon operations should import the
selected compatibility types from this crate: `Macaroon` and `MacaroonKey`.
The underlying
`macaroon-decmed` crate remains an implementation dependency of
`decmed-macaroon-auth` and should not be declared directly by consumers.

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

Active identity is derived from `root_subject` and the
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

`issue_admin_personnel_token` signs AdministrativePersonnel grants with the PRE root key (from
`MACAROON_ROOT_KEY`). Clients receive only the serialized macaroon.

Administrative grants issue separate read/update macaroons. The read token stays patient-scoped,
while the update token may carry `related_rme_id` to bind all writes and downstream clinical
delegations to one RME episode.

## Delegated token (PRE)

`attenuate_macaroon` appends caveats without the root key, but production delegation is requested
through PRE. PRE validates the parent token, delegator signature, revocation/delegation proof, and
on-chain access snapshot before returning the attenuated token. Clients sign the final delegation
proof, encrypt delegatee metadata, and record the result to IOTA.

## PRE verification

1. Verify macaroon HMAC with root key.
2. Match `patient_address` / `related_rme_id`.
3. Validate delegation chain and `max_delegation_depth`.
4. Verify the mandatory IOTA ED25519 signature over `WalletProofContext` JSON from `active_subject`.
5. Intersect caveats → allow READ/WRITE only when dataset + function categories match segment metadata.

## Segment metadata

Use `RmeSegmentMetadata` (`decmed-rme-segment`) fields: `segment_id`, `patient_address`, `related_rme_id`, `dataset_category`, `function_category`.
