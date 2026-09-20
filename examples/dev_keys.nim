# DEV-ONLY demo keys for the examples/ showcase. NEVER use in production.
#
# These fixed seeds exist so the example is deterministic and runnable
# without any setup. The private seeds below may appear ONLY in the
# development minting tool (mint_license.nim) and the local mock server
# (mock_license_server.nim). premium_cli.nim embeds ONLY the derived
# public keys (see demo_pubkeys.nim) and must never import this module.
#
# Production: sign licenses with a protected key (signing service or
# HSM); the application embeds only public verification keys.

import std/os
import std/strformat
import std/strutils

import ./demo_pubkeys

export demo_pubkeys

const
  LicenseSeedFile* = "license.seed"
  OnlineSeedFile* = "online.seed"
  DefaultKeysDir* = "examples/keys"

proc demoLicenseSeed*(): array[32, byte] =
  ## Fixed DEMO seed for the offline license signing key.
  for i in 0 ..< 32:
    result[i] = byte(101 + i)

proc demoOnlineSeed*(): array[32, byte] =
  ## Fixed DEMO seed for the online-response signing key.
  ## Always a different key from the license signing key.
  for i in 0 ..< 32:
    result[i] = byte(201 + i)

proc bytesToHex*(data: array[32, byte]): string =
  ## Hex-encode 32 bytes (a seed for storage, or a pubkey for display).
  for b in data:
    result.add(fmt"{b:02x}")

proc seedFromHex*(s: string): array[32, byte] =
  ## Decode a 64-char hex seed file. Raises ValueError on bad input.
  let t = s.strip()
  if t.len != 64:
    raise newException(ValueError, "seed must be 64 hex chars")
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(t[2 * i .. 2 * i + 1]))

proc saveSeed*(dir, name: string, seed: array[32, byte]) =
  ## Persist a generated seed to dir/name (gitignored, local only).
  createDir(dir)
  writeFile(dir / name, bytesToHex(seed) & "\n")

proc loadSeed*(dir, name: string): array[32, byte] =
  ## Load a persisted seed. Raises on missing file or bad content.
  seedFromHex(readFile(dir / name))

proc pubkeyNimLiteral*(pub: array[32, byte]): string =
  ## Render a public key as a Nim array literal for demo_pubkeys.nim.
  result = "["
  for i in 0 ..< 32:
    if i > 0:
      result.add(", ")
    if i mod 8 == 0:
      result.add("\n    ")
    result.add(fmt"0x{pub[i]:02x}")
  result.add("]")
