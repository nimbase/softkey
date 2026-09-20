# Keys for the examples/ showcase

## What lives here

No keys are checked in. At runtime this directory may hold locally
generated `license.seed` / `online.seed` files (gitignored) written by
`mint_license.nim`; the fixed DEMO private seeds live in
`examples/dev_keys.nim` (source code, `--demo-seed` only,
non-production); the public keys that `premium_cli` embeds live in
`examples/demo_pubkeys.nim`.

## Rules

- **Public keys** (`demo_pubkeys.nim`): safe to embed in the app and
  to check in. They verify signatures but cannot create them.
- **Private keys** (`dev_keys.nim` seeds, or generated `*.seed`
  files): development fixtures only, used by `mint_license.nim` and
  `mock_license_server.nim`. They are NOT production-safe and must
  never sign real licenses.
- **Production signing keys** belong on a protected signing system
  or HSM. They never appear in application source, in this directory,
  or in version control.
- **The application embeds only public verification keys** and
  allowlists them by `kid`:
  - offline license key: `kid = example-license-2026-01`
  - online response key: `kid = example-online-2026-01`
- Never accept a public key, JWK, or algorithm supplied by the token
  itself; the allowlist is compiled in.

## Generated files (gitignored)

Local development artifacts such as `*.key`, `*.jwk`, and minted
`*.lic` token files belong here when experimenting, and are ignored
by version control (see `.gitignore`).
