# Development license minter for the examples/ showcase.
#
# NEVER compile this into the shipped application. It holds the DEMO
# private signing seed, which is NOT production-safe: it is checked in
# so the example runs without setup. Production licenses must be
# signed by a protected signing service or HSM.
#
# Usage:
#   clue build examples/mint_license.nim --out:mint_license
#   ./mint_license --jti:license-001 --plan:demo --days:30 \
#       --features:run --customer:example-customer
#
# Prints the compact JWS license token plus the DEMO public keys
# (which are the only key material premium_cli.nim may embed).

import std/json
import std/parseopt
import std/strformat
import std/strutils
import std/times

import jose

import ./dev_keys

proc hexOf(data: array[32, byte]): string =
  for b in data:
    result.add(fmt"{b:02x}")

proc main() =
  var jti = "license-001"
  var plan = "demo"
  var days = 30
  var features = @["run"]
  var customer = "example-customer"
  for kind, key, val in getopt():
    case key
    of "jti": jti = val
    of "plan": plan = val
    of "days": days = parseInt(val)
    of "features": features = val.split(',')
    of "customer": customer = val
    else: discard

  let seed = demoLicenseSeed()
  let priv = jwkOkpFromSeed(seed, DemoLicenseKid)
  echo "WARNING: demo signing key, NOT production-safe."
  echo "license pubkey kid: ", DemoLicenseKid
  echo "license pubkey hex: ", hexOf(priv.okpPub)
  let onlinePriv = jwkOkpFromSeed(demoOnlineSeed(), DemoOnlineKid)
  echo "online pubkey kid: ", DemoOnlineKid
  echo "online pubkey hex: ", hexOf(onlinePriv.okpPub)

  let now = getTime().toUnix()
  var feats = newJArray()
  for f in features:
    feats.add(%f)
  let payload = %*{
    "iss": DemoIss,
    "aud": DemoAud,
    "sub": jti,
    "jti": jti,
    "iat": now,
    "nbf": now,
    "exp": now + int64(days) * 24 * 3600,
    "plan": plan,
    "features": feats,
    "customer_id": customer
  }
  echo "token: ", jwsSign(EdDSA, priv, $payload)

when isMainModule:
  main()
