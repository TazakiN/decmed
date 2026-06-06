# Decmed Deployment & Operation Guide

This guide provides the necessary commands to publish smart contracts to IOTA, interact with the wallet, and run various components of the Decmed ecosystem.

## 1. IOTA Smart Contract (Move) Publishing

To publish the smart contract to the IOTA network (specifically Move-based IOTA), follow these steps:

### Prerequisites
- Ensure you have the `iota` CLI installed.
- Your `Move.toml` should be correctly configured with the IOTA framework dependencies.

### Publishing Command
Navigate to the directory containing your Move package (e.g., `move/decmed`):
```bash
cd move/decmed
iota client publish --gas-budget 300000000
```
*Note: Ensure you have enough gas in your active address.*

### Checking Deployment
After publishing, you will see the `PackageID` in the output. You can also check your objects:
```bash
iota client objects
```

---

## 2. Wallet Interaction

### Check Active Address
```bash
iota client active-address
```

### Check Balance (Gas Objects)
```bash
iota client gas
```

### Request Testnet Tokens (Faucet)
You can request tokens via CLI or API:
**CLI:**
```bash
iota client faucet --address <YOUR_ADDRESS>
```
**API (Postman/Curl):**
- URL: `https://faucet.testnet.iota.io/api/enqueue`
- Method: `POST`
- Body: `{"address": "YOUR_IOTA_ADDRESS_HERE"}`

---

## 3. Docker Commands

### Gas Station
Gas station requires a configuration file before starting.
```bash
cd gas-station/docker
# Generate sample config (ensure tool is built via 'cargo build' in gas-station root)
../target/debug/tool generate-sample-config --docker-compose --config-path config.yaml --network testnet
# Run Docker
docker compose up
```

### IPFS Cluster
```bash
cd ipfs-cluster-ctl
docker compose up
```
*Wait for the containers to initialize. This will start 3 peer nodes.*

---

## 4. Proxy Re-encryption & Tauri

### Running Proxy Re-encryption Service
This service must be running for the Tauri client to function properly.
```bash
cd proxy-reencryption
docker compose up
```

### Running Tauri Client
Navigate to the hospital client directory and run the development server:
```bash
cd client/client-hospital-tauri
pnpm install
pnpm tauri dev
```
*Or if you prefer using cargo:*
```bash
cd client/client-hospital-tauri/src-tauri
cargo tauri dev
```

For multi-account hospital demos, launch separate app instances with different profiles:
```bash
DEC_MED_PROFILE=admin ./client-hospital-tauri
DEC_MED_PROFILE=doctor ./client-hospital-tauri
DEC_MED_PROFILE=nurse ./client-hospital-tauri
DEC_MED_PROFILE=lab ./client-hospital-tauri
```
Each profile uses a separate keyring namespace. For the most predictable multi-instance demo,
build the executable once and launch the generated binary multiple times with different
`DEC_MED_PROFILE` values. Running multiple `pnpm tauri dev` processes can collide on Vite's fixed
port `1420`.

---

## 5. Macaroon caveats (RME fine-grained access)

See `crates/decmed-macaroon-auth/README.md` for caveat format, effective access (intersection), and delegation rules.

| Step | Mechanism |
|------|-----------|
| Initial token | `POST /api/v1/keys` with `related_rme_id` — PRE signs with `MACAROON_ROOT_KEY` |
| Delegation | Hospital Tauri `delegate_macaroon` — append-only caveats, no root key |
| PRE access | Bearer macaroon; segment routes also use `x-decmed-wallet-signature` when `proof_required = wallet_signature` |
| Active actor | `delegated_to` terakhir, atau `root_subject` — **bukan** `holder_address` |

Tests: `cd crates/decmed-macaroon-auth && cargo test`
