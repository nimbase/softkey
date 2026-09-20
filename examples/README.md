# premium_cli example: gating a Nim app on a softkey license

This is a showcase of how to integrate `softkey` into a Nim
application. `premium_cli` performs no cryptography of its own: every
license decision is delegated to the library (`validateLicenseOffline`,
`validateLicense`, `isAccepted`, `httpOnlineChecker`). The protected
operation is a placeholder two-line success message.

## Prerequisites

- Nim >= 2.2.12 and the `clue` toolchain.
- Dependencies from the project root: `clue install jose nimcypher`.

## Build

From the repository root:

```bash
clue build examples/mint_license.nim --out:mint_license
clue build examples/premium_cli.nim --out:premium_cli
clue build examples/mock_license_server.nim --out:mock_license_server
```

`mint_license` and `mock_license_server` are development fixtures and
must never ship. `premium_cli` embeds only public keys.

## Mint a demo license

```bash
./mint_license --jti:license-001 --plan:demo --days:30 \
    --features:run --customer:example-customer
```

This prints a `token: <compact JWS>` line. Save it:

```bash
./mint_license --jti:license-001 --plan:demo --days:30 \
    --features:run --customer:example-customer | grep '^token: ' | cut -d' ' -f2 > license.lic
```

WARNING: the demo signing key is checked in and NOT production-safe.
Production licenses must be signed by a protected signing service
or HSM.

## Offline validation

```bash
./premium_cli --license-file license.lic verify-offline
./premium_cli --license-file license.lic inspect
./premium_cli --license-file license.lic run
```

Expected output for `run`:

```text
Protected operation succeeded.
The license permits this operation.
```

Offline policy: the token's `exp` controls expiration, and the
library additionally rejects any token whose total lifetime exceeds
90 days (60s clock-skew allowance). Offline validation cannot detect
server-side revocation; for that, use the online check below.

## Online verification

```bash
./mock_license_server --port:18081 &
./premium_cli --license-file license.lic verify-online --url http://127.0.0.1:18081
./premium_cli --license-file license.lic run --url http://127.0.0.1:18081
```

The CLI validates offline first, hashes the exact token (SHA-256),
generates a fresh nonce per request, and verifies the server's signed
JWS reply (separate online key, `example-online-2026-01`). Network
timeout defaults to 2000ms (`--timeout-ms`). Policy flags:

- default (fail-open): unreachable server is reported, a valid
  offline license still runs.
- `--online-required`: any network failure or bad reply denies.
- `--offline-if-unavailable`: explicit fail-open with a clear notice.
- A signed `revoked` reply always denies, in every mode.

## Attacker / failure modes

Each mode simulates a fake or broken server. The CLI must reject
every one (mapping to `onlineUnavailable`, never a positive verdict):

```bash
./mock_license_server --port:18082 --mode:unsigned
./mock_license_server --port:18082 --mode:random-key
./mock_license_server --port:18082 --mode:wrong-nonce
./mock_license_server --port:18082 --mode:wrong-license
./mock_license_server --port:18082 --mode:expired
./mock_license_server --port:18082 --mode:malformed
./premium_cli --license-file license.lic run --url http://127.0.0.1:18082 --online-required
# -> premium_cli: error: online verification required but unavailable (exit 1)
```

Revocation:

```bash
./mock_license_server --port:18083 --status:revoked
./premium_cli --license-file license.lic run --url http://127.0.0.1:18083
# -> premium_cli: error: license revoked by the server (exit 1)
```

## Security limitations

- JWS provides authenticity and integrity; JWE is not used here and
  the license contents are readable by anyone holding the token.
- The client embeds public keys only; no secrets ship with the app.
- Signed online responses stop fake servers from producing accepted
  responses, but a locally patched client can always skip validation.
  Client-side checks raise the bar; they are not a trust boundary.
- Offline licenses cannot be reliably revoked without online checks
  or signed revocation data.
- No anti-debugging, integrity checks, or obfuscation are included;
  those are outside the scope of this example.
