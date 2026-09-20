# Development license minter for the examples/ showcase.
#
# NEVER compile this into the shipped application. It creates or holds
# private signing keys, which are NOT production-safe. Production
# licenses must be signed by a protected signing service or HSM.
#
# Default: use the keypairs in examples/keys/ (gitignored, local
# only), generating two FRESH keypairs (license + online) on first run,
# and print the compact JWS plus the public keys to embed:
#   clue build examples/mint_license.nim --out:mint_license
#   ./mint_license --pubkeys-out:examples/demo_pubkeys.nim
#   clue build examples/premium_cli.nim --out:premium_cli
#
# Pass --rotate to throw the current keys away and generate new ones
# (previously minted tokens stop verifying; rebuild the CLI).
#
# Deterministic demo mode (reproducible docs/tests, fixed seeds):
#   ./mint_license --demo-seed --jti:license-001 --plan:demo \
#       --days:30 --features:run --customer:example-customer

import std/json
import std/parseopt
import std/strutils
import std/times

import jose

import ./dev_keys

proc main() =
  var jti = "license-001"
  var plan = "demo"
  var days = 30
  var features = @["run"]
  var customer = "example-customer"
  var useDemoSeed = false
  var rotate = false
  var keysDir = DefaultKeysDir
  var pubkeysOut = ""
  for kind, key, val in getopt():
    case key
    of "jti": jti = val
    of "plan": plan = val
    of "days": days = parseInt(val)
    of "features": features = val.split(',')
    of "customer": customer = val
    of "demo-seed": useDemoSeed = true
    of "rotate": rotate = true
    of "keys-dir": keysDir = val
    of "pubkeys-out": pubkeysOut = val
    else: discard

  var licKey, onlKey: Jwk
  if useDemoSeed:
    licKey = jwkOkpFromSeed(demoLicenseSeed(), DemoLicenseKid)
    onlKey = jwkOkpFromSeed(demoOnlineSeed(), DemoOnlineKid)
    echo "WARNING: fixed DEMO seeds, NOT production-safe."
  else:
    var loaded = false
    if not rotate:
      try:
        licKey = jwkOkpFromSeed(loadSeed(keysDir, LicenseSeedFile),
          DemoLicenseKid)
        onlKey = jwkOkpFromSeed(loadSeed(keysDir, OnlineSeedFile),
          DemoOnlineKid)
        loaded = true
        echo "reusing local keys from " & keysDir & "/"
      except CatchableError:
        discard
    if not loaded:
      licKey = jwkEd25519Generate(DemoLicenseKid)
      onlKey = jwkEd25519Generate(DemoOnlineKid)
      saveSeed(keysDir, LicenseSeedFile, licKey.okpSeed)
      saveSeed(keysDir, OnlineSeedFile, onlKey.okpSeed)
      echo "WARNING: freshly generated LOCAL keys, NOT production-safe."
      echo "seeds saved to " & keysDir & "/ (gitignored, do not commit)"

  echo "license pubkey kid: ", DemoLicenseKid
  echo "license pubkey hex: ", bytesToHex(licKey.okpPub)
  echo "online pubkey kid: ", DemoOnlineKid
  echo "online pubkey hex: ", bytesToHex(onlKey.okpPub)

  if pubkeysOut.len > 0:
    let content = """# Public verification keys for premium_cli. Safe to embed.
#
# GENERATED locally by mint_license.nim. Matches the seeds in
# examples/keys/ (gitignored). Rebuild premium_cli after rewriting.
# With --demo-seed this file matches the checked-in demo keys.

const
  DemoLicenseKid* = """" & DemoLicenseKid & """"
  DemoOnlineKid* = """" & DemoOnlineKid & """"
  DemoIss* = """" & DemoIss & """"
  DemoAud* = """" & DemoAud & """"
  DemoOnlineAud* = """" & DemoOnlineAud & """"

  DemoLicensePubkey*: array[32, byte] = """ &
      pubkeyNimLiteral(licKey.okpPub) & """

  DemoOnlinePubkey*: array[32, byte] = """ &
      pubkeyNimLiteral(onlKey.okpPub) & "\n"
    writeFile(pubkeysOut, content)
    echo "pubkeys written to " & pubkeysOut & "; rebuild premium_cli"

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
  echo "token: ", jwsSign(EdDSA, licKey, $payload)

when isMainModule:
  main()
