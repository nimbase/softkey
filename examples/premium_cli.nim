# premium_cli: showcase of how to integrate softkey into a Nim app.
#
# This CLI performs NO cryptography of its own. Every license decision
# is delegated to the softkey library:
#   offline check -> validateLicenseOffline()
#   online check  -> validateLicense() + httpOnlineChecker()
#   final gate    -> isAccepted()
#
# It embeds ONLY public verification keys (demo_pubkeys.nim). No
# private key material is present here or reachable from here.

import std/options
import std/os
import std/strutils
import std/times

import softkey

import ./demo_pubkeys

const
  RequiredFeature = "run"
  DefaultTimeoutMs = 2000

proc usage() =
  echo """premium_cli: example protected operation gated by a softkey license.

Usage:
  premium_cli --help
  premium_cli --license <token> run [--url <base>] [--online-required | --offline-if-unavailable] [--timeout-ms <n>]
  premium_cli --license-file <path> run [online options...]
  premium_cli --license <token> inspect
  premium_cli --license <token> verify-offline
  premium_cli --license <token> verify-online --url <base> [--timeout-ms <n>]

Online policy:
  default (fail-open): an unreachable server is reported but a valid
    offline license still runs. A signed "revoked" reply always denies.
  --online-required: any network failure or bad reply denies execution.
  --offline-if-unavailable: explicit fail-open; reports unavailability.
"""

proc fail(msg: string): void =
  stderr.writeLine("premium_cli: error: " & msg)
  quit(1)

proc offlineKeys(): seq[TrustedKey] =
  @[TrustedKey(kid: DemoLicenseKid, pubkey: DemoLicensePubkey)]

proc onlineKeys(): seq[TrustedKey] =
  @[TrustedKey(kid: DemoOnlineKid, pubkey: DemoOnlinePubkey)]

proc loadToken(license, licenseFile: string): string =
  if license.len > 0:
    return license.strip()
  if licenseFile.len > 0:
    try:
      return readFile(licenseFile).strip()
    except CatchableError:
      fail("cannot read license file: " & licenseFile)
  fail("missing license: pass --license <token> or --license-file <path>")

proc checkOffline(token: string): License =
  let (status, lic) = validateLicenseOffline(token, offlineKeys(),
    DemoIss, DemoAud, getTime().toUnix())
  case status
  of valid: discard
  of malformed: fail("malformed license token")
  of badSignature: fail("invalid license signature")
  of wrongAlgorithm: fail("unsupported license algorithm")
  of unknownKey: fail("license signed by an unknown key")
  of wrongIssuer: fail("license not issued for this authority")
  of wrongAudience: fail("license not authorized for this product")
  of expired: fail("license has expired")
  of notYetValid: fail("license is not yet valid (check clock)")
  of lifetimeTooLong: fail("license lifetime exceeds the 90-day maximum")
  of unsupportedBinding: fail("license device binding is unsupported")
  of revoked: fail("license is revoked")
  lic

proc checkFeature(lic: License) =
  if RequiredFeature notin lic.features:
    fail("license does not permit this operation (missing '" &
      RequiredFeature & "' feature)")

proc runOnline(token, url: string, timeoutMs: int,
    onlineRequired, offlineIfUnavailable: bool): OnlineStatus =
  var policy = defaultOnlinePolicy(url)
  policy.timeoutMs = timeoutMs
  if onlineRequired:
    policy.allowUnavailable = false
    policy.requireOnline = true
  let checker = httpOnlineChecker(policy, onlineKeys(), DemoIss,
    DemoOnlineAud)
  let res = validateLicense(token, offlineKeys(), DemoIss, DemoAud,
    getTime().toUnix(), some(checker), policy)
  if res.online == onlineRevoked:
    fail("license revoked by the server")
  if res.offline != valid:
    fail("offline license invalid; online check skipped")
  case res.online
  of onlineValid:
    echo "online verification: valid"
  of onlineRevoked:
    fail("license revoked by the server")
  of renewalRequired:
    echo "online verification: renewal required"
  of onlineUnavailable:
    if onlineRequired:
      fail("online verification required but unavailable")
    elif offlineIfUnavailable:
      echo "online verification unavailable; proceeding offline (explicit fallback)"
    else:
      echo "online verification unavailable; proceeding offline (default fail-open)"
  of onlineNotChecked:
    fail("online check did not run")
  if not isAccepted(res, policy):
    fail("license not accepted under the online policy")
  res.online

proc main() =
  var license = ""
  var licenseFile = ""
  var url = ""
  var timeoutMs = DefaultTimeoutMs
  var onlineRequired = false
  var offlineIfUnavailable = false
  var command = ""
  var i = 1
  proc takeValue(flag, inlineVal: string): string =
    ## Accepts --flag value, --flag=value, and --flag:value forms.
    if inlineVal.len > 0:
      return inlineVal
    inc i
    if i > paramCount():
      fail("missing value for " & flag)
    paramStr(i)
  while i <= paramCount():
    var a = paramStr(i)
    var inlineVal = ""
    if a.startsWith("--"):
      let eq = a.find('=')
      let co = a.find(':')
      var cut = -1
      if eq > 2 and (co <= 2 or eq < co):
        cut = eq
      elif co > 2:
        # Keep http://... intact: only split --url:http... on the
        # colon right after the flag name... actually the first colon
        # after "--" always ends the flag name, the rest is the value.
        cut = co
      if cut > 2:
        inlineVal = a[cut + 1 .. ^1]
        a = a[0 ..< cut]
    case a
    of "--help", "-h":
      usage()
      quit(0)
    of "--license":
      license = takeValue("--license", inlineVal)
    of "--license-file":
      licenseFile = takeValue("--license-file", inlineVal)
    of "--url":
      url = takeValue("--url", inlineVal).strip(chars = {'/'})
    of "--timeout-ms":
      let raw = takeValue("--timeout-ms", inlineVal)
      try:
        timeoutMs = parseInt(raw)
      except ValueError:
        fail("invalid --timeout-ms value")
      if timeoutMs <= 0 or timeoutMs > 60000:
        fail("invalid --timeout-ms value (1..60000)")
    of "--online-required":
      onlineRequired = true
    of "--offline-if-unavailable":
      offlineIfUnavailable = true
    of "run", "inspect", "verify-offline", "verify-online":
      if command.len > 0: fail("only one command expected")
      command = a
    else:
      fail("unknown argument: " & a & " (see --help)")
    inc i
  if onlineRequired and offlineIfUnavailable:
    fail("--online-required and --offline-if-unavailable are exclusive")
  if command.len == 0:
    fail("missing command (run, inspect, verify-offline, verify-online)")

  let token = loadToken(license, licenseFile)
  case command
  of "verify-offline":
    let lic = checkOffline(token)
    echo "offline: valid plan=" & lic.plan & " features=" &
      lic.features.join(",")
  of "inspect":
    let lic = checkOffline(token)
    echo "plan: " & lic.plan
    echo "features: " & lic.features.join(",")
    echo "customer: " & lic.customerId
    echo "license id: " & lic.id
    echo "expires: " & $lic.expiresAt
  of "verify-online":
    if url.len == 0:
      fail("verify-online requires --url <base>")
    discard checkOffline(token)
    discard runOnline(token, url, timeoutMs, onlineRequired,
      offlineIfUnavailable)
  of "run":
    let lic = checkOffline(token)
    checkFeature(lic)
    if url.len > 0:
      discard runOnline(token, url, timeoutMs, onlineRequired,
        offlineIfUnavailable)
    echo "Protected operation succeeded."
    echo "The license permits this operation."
  else:
    fail("unknown command")

when isMainModule:
  main()
