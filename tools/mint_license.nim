# Server-only license minter. Never ship with the application.
#
# Usage (example):
#   clue build tools/mint_license.nim --out:mint_license
#   ./mint_license  # prints a test token + public key hex
#
# Production: load the 32-byte Ed25519 seed from an HSM / vault,
# keep it offline, and emit compact JWS tokens with kid rotation.

import std/json
import std/strformat

import jose

const
  TestKid = "license-signing-key-2026-01"
  TestIss = "your-company"
  TestAud = "your-product"

proc seedFromInts(): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = byte(i + 1)

proc main() =
  let seed = seedFromInts()
  let priv = jwkOkpFromSeed(seed, TestKid)
  echo "pubkey kid: ", TestKid
  var hex = ""
  for b in priv.okpPub:
    hex.add(fmt"{b:02x}")
  echo "pubkey hex: ", hex

  var b = initJwtBuilder()
  b.iss(TestIss)
  b.sub("license-01J")
  b.aud(TestAud)
  b.jti("unique-license-token-id")
  b.iat(1760000000)
  b.exp(1760000000 + 30 * 24 * 3600) # 30 days, within MaxOfflineLifetime
  b.claim("plan", "pro")
  b.claim("features", %*["export", "batch-processing"])
  b.claim("max_seats", 5'i64)
  b.claim("customer_id", "opaque-customer-id")
  b.claim("binding", %*{"type": "none"})
  let token = jwtSign(b, EdDSA, priv)
  echo "token: ", token

when isMainModule:
  main()
