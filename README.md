<p align="center">
  Offline-first software licensing for Nim: compact JWS + Ed25519 verification,<br>
  strict offline policy, optional online revocation, opt-in anti-debug gate<br>
</p>

<p align="center">
  <code>clue install softkey</code> (or <code>nimble install softkey</code>)
</p>

<p align="center">
  <a href="https://nimbase.github.io/softkey/">API reference</a><br>
  <img src="https://github.com/nimbase/softkey/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/softkey/workflows/docs/badge.svg" alt="Github Actions">
</p>


## Features
- Signature-first license checks
- Strict, predictable license contents
- Client-side lifetime limits
- Reserved device binding
- Advisory online revocation
- Signed server replies with enforced feature narrowing
- Complete dev and red-team tooling, no shipped secrets
- Small footprint on the standard library
- Optional tamper sensing with a dev bypass

## Feature details
#### Signature-first license checks
Every license is verified as a tamper-proof signed token against an approved key list before any of its contents are trusted.
#### Strict, predictable license contents
All required fields must be present and correctly typed, duplicate entries are rejected, and oversized tokens are refused.
#### Client-side lifetime limits
The app caps how long any license may last, with a small allowance for clock differences, so even a valid signature cannot grant a decades-long license.
#### Reserved device binding
Unbound licenses work today, while hardware-bound licenses are recognized as unsupported until that enforcement is built.
#### Advisory online revocation
Offline validation always runs first and decides on its own; the server can only add revocation or renewal signals, and the app decides whether an unreachable server fails open or closed.
#### Signed server replies
Status answers are signed, tied to the exact license shown and a fresh per-request number, expire after five minutes, and may only narrow (never widen) the feature list; unsigned answers are ignored entirely.
#### Complete dev and red-team tooling
A server-only license signer, a local test server, and an attacker simulator with a scorecard proving forged verdicts never yield a positive signal; no private keys are ever shipped inside the app.
#### Small footprint
Two well-known cryptography libraries on a recent Nim toolchain, with network checks built on the standard library alone.
#### Optional tamper sensing
The app can ask to be told when a debugger is attached and shut itself down; developers can switch this off for everyday work. It slows casual tampering but is not a security boundary.

## Examples
Offline validation (deterministic, no network):

```nim
import std/times
import softkey

# the single approved signing key, selected by its id
let keys = @[TrustedKey(kid: "license-signing-key-2026-01", pubkey: prodPub)]

# checks the license signature, claims, and lifetime, all offline
let (status, lic) = validateLicenseOffline(token, keys,
  "your-company", "your-product", getTime().toUnix())
if status != valid:
  deny(status)
else:
  echo lic.plan, " ", lic.features
```

Combined offline + online revocation check (fail-open):

```nim
import std/options
import std/times
import softkey

let keys = @[TrustedKey(kid: "license-signing-key-2026-01", pubkey: prodPub)]
let now = getTime().toUnix()

# checks the revocation server address and the fail-open policy
let policy = defaultOnlinePolicy("http://127.0.0.1:18080")

# checks signed server replies against the trusted keys
let checker = httpOnlineChecker(policy, keys, "your-company",
  "your-product")

# checks offline validity first, then layers the online verdict on top
let res = validateLicense(token, keys, "your-company",
  "your-product", now, some(checker), policy)
if res.offline != valid or not isAccepted(res, policy):
  deny(res)
```

Local mock workflow:

```bash
clue install jose nimcypher
clue build tools/mock_server.nim --out:mock_server
./mock_server --port:18080 --seed:tools/revocations.json
clue test
```

Red-team workflow (adversarial fixture, localhost only):

```bash
clue build tools/hacker_server.nim --out:hacker_server
clue build tools/redteam.nim --out:redteam
./redteam --port:18080
```

Expected oracle: unsigned forgery, random-key signatures, retired
kids, wrong nonces/hashes, widened features, stale windows and
blackholes all map to `onlineUnavailable` (never a positive verdict);
acceptance then follows the fail-open / `requireOnline` policy. R2t
random-key license tokens stay denied offline.

Anti-debug gate (opt-in; library raises, app terminates):

```nim
import std/options
import std/times
import softkey

let keys = @[TrustedKey(kid: "license-signing-key-2026-01", pubkey: prodPub)]
let now = getTime().toUnix()
try:
  # Offline-only with gate:
  let (status, lic) = validateLicenseOffline(token, keys,
    "your-company", "your-product", now,
    defaultAntiDebugPolicy())

  # Or combined with online revocation (checker/policy as above):
  # let res = validateLicense(token, keys, "your-company",
  #   "your-product", now, some(checker), policy,
  #   defaultAntiDebugPolicy())
except DebuggerDetected:
  quit(1)
```

Dev bypass (debug with softkey enabled; `clue build` has no
`--define` passthrough, so set it in your app's `config.nims`):

```nims
# config.nims (dev only, never ship)
switch("define", "softkeyNoAntidebug")
```

## Roadmap
- [x] Strict offline validator (compact JWS + EdDSA, client-capped lifetime)
- [x] Advisory online composition (`CombinedResult` + `isAccepted`, fail-open default)
- [x] Stdlib mock server with memory + JSON-file revocations
- [x] Opt-in anti-debug gate (`DebuggerDetected` + `-d:softkeyNoAntidebug` dev bypass)
- [x] Signed + nonce-bound status replies (dedicated license-key signatures, 300s window, enforced feature subsets; redteam R1 now yields unavailable, never valid)
- [ ] Short-lived token guidance (7-30 day `exp`)
- [ ] Per-action fail-open / fail-closed policy
- [ ] `ed25519` device-key binding enforcement
- [ ] Production server auth + TLS pinning, seat / lease tracking
- Non-goals: self-hash hardening (excluded), JWE-embedded decryption secrets (rejected by design; public verification keys only).

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/softkey/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/softkey/fork)

### 🎩 License
MIT license | Nim Community.
