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
- Ed25519-only compact JWS verification: `allowAlgs = [EdDSA]`, `kid` allowlist lookup, signature verified before any claim is trusted.
- Strict claims profile: required `iss`, `aud`, `sub`, `jti`, `plan`, `customer_id`, `iat`, `exp`; `JInt`-only timestamps; duplicate top-level members rejected; 8KB token cap.
- Client-capped lifetime: 90-day `MaxOfflineLifetime`, 60s clock leeway, future-`iat` guard; over-long tokens return `lifetimeTooLong` even with a valid signature.
- Binding schema reserved: `binding: {"type": "none"}` enforced in Phase 1; `ed25519` device binding returns `unsupportedBinding` until enforcement lands.
- Advisory online layer: deterministic offline check plus `CombinedResult{offline, online}` revocation signals keyed by `jti`; fail-open default with explicit `isAccepted()` gate.
- Signed status replies: `POST /v1/licenses/verify` with `{jti, license_hash, nonce}` returns compact JWS (EdDSA, same license key); client enforces signature, `iss`/`aud`, nonce and hash binding, 300s freshness window, and reply-features-subset-of-license; bare `{"status": ...}` is never honored.
- Dev tooling included: server-only `tools/mint_license.nim` signer, stdlib-only `tools/mock_server.nim` with `tools/revocations.json` seed; adversarial `tools/hacker_server.nim` + `tools/redteam.nim` oracle proving forged verdicts never yield a positive signal while R2t random-key license tokens stay denied offline; no private keys ship in the binary.
- Minimal dependencies: `jose#HEAD` + `nimcypher >= 0.2.4` on Nim `>= 2.2.12`; online transport is stdlib HTTP only.
- Opt-in anti-debug gate: `enforceNoDebugger()` raises `DebuggerDetected` (app terminates); `-d:softkeyNoAntidebug` bypasses for dev work; tamper resistance only, not a trust boundary.

## Examples
Offline validation (deterministic, no network):

```nim
import std/times
import softkey

let keys = @[TrustedKey(kid: "license-signing-key-2026-01", pubkey: prodPub)]
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
let policy = defaultOnlinePolicy("http://127.0.0.1:18080")
let checker = httpOnlineChecker(policy, keys, "your-company",
  "your-product")
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
