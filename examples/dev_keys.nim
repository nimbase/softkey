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

const
  DemoLicenseKid* = "example-license-2026-01"
  DemoOnlineKid* = "example-online-2026-01"
  DemoIss* = "example-license-authority"
  DemoAud* = "nim-license-example"
  DemoOnlineAud* = "nim-license-example-online"

proc demoLicenseSeed*(): array[32, byte] =
  ## Fixed DEMO seed for the offline license signing key.
  for i in 0 ..< 32:
    result[i] = byte(101 + i)

proc demoOnlineSeed*(): array[32, byte] =
  ## Fixed DEMO seed for the online-response signing key.
  ## Always a different key from the license signing key.
  for i in 0 ..< 32:
    result[i] = byte(201 + i)
