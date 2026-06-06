# Tauri + SvelteKit + TypeScript

This template should help get you started developing with Tauri, SvelteKit and TypeScript in Vite.

## Multi-profile sessions

Hospital Client stores credentials in the OS keyring. For demos that need multiple hospital
personnel accounts open at the same time, start each app instance with a different profile:

```bash
DEC_MED_PROFILE=admin ./client-hospital-tauri
DEC_MED_PROFILE=doctor ./client-hospital-tauri
DEC_MED_PROFILE=nurse ./client-hospital-tauri
DEC_MED_PROFILE=lab ./client-hospital-tauri
DEC_MED_PROFILE=apoteker ./client-hospital-tauri
```

The app also accepts a CLI argument:

```bash
./client-hospital-tauri --profile doctor
```

If both are provided, `--profile` takes precedence over `DEC_MED_PROFILE`. If neither is
provided, the active profile is `default`.

Each profile uses its own keyring service:

```text
decmed_service_keys:<profile_id> / decmed_user
```

For example, `admin` and `doctor` write to separate keyring entries, so signing out or resetting
one profile does not clear another profile's credentials.

For development demos, running multiple `pnpm tauri dev` commands directly can fail because Vite
uses fixed port `1420` with `strictPort: true`. The safest workflow is to build once, then launch
multiple executable instances with different `DEC_MED_PROFILE` values. Use `pnpm tauri build`,
then run the generated binary for each profile.

## Recommended IDE Setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
