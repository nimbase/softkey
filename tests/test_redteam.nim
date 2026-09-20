# Red-team regression tests: attacker controls the endpoint.
# Signed replies: forgery must never yield a positive verdict.
# R2t token variants always run (no server). Server phases need
# ./mock_server + ./hacker_server built, else they skip gracefully.
# Run with: clue test (uses port 18081 to avoid the dev mock)
#
# Expectation key ("rejected" = never honored as a verdict):
#   R0 blackhole: onlineUnavailable, acceptance follows policy
#   R1 unsigned forgery: onlineUnavailable, acceptance follows policy
#   R2 forged-signed reply: onlineUnavailable
#   R3 chaos: onlineUnavailable
#   R4 wrong nonce / R5 wrong hash / R6 unknown key: onlineUnavailable

import std/json
import std/net
import std/options
import std/os
import std/osproc
import std/strutils
import std/sysrand
import std/times
import unittest

import jose
import softkey

const
  TestKid = "license-signing-key-2026-01"
  TestIss = "your-company"
  TestAud = "your-product"
  BaseNow = 1760000000'i64
  RedPort = 18081

proc testSeed(): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = byte(i + 1)

proc trusted(): seq[TrustedKey] =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  @[TrustedKey(kid: TestKid, pubkey: priv.okpPub)]

proc mintRevoked(now = BaseNow): string =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  let payload = %*{
    "iss": TestIss, "aud": TestAud, "sub": "license-01J",
    "iat": now, "exp": now + 30 * 24 * 3600,
    "jti": "revoked-license-001", "plan": "pro",
    "features": ["export"], "max_seats": 5, "customer_id": "c1",
    "binding": {"type": "none"}
  }
  jwsSign(EdDSA, priv, $payload)

proc devStatusKey(): Jwk =
  jwkOkpFromSeed(testSeed(), TestKid)

proc signStatus(payload: JsonNode, key = devStatusKey()): string =
  jwsSign(EdDSA, key, $payload)

proc statusPayload(nonce, hash, status: string, now: int64,
    feats = @["export"]): JsonNode =
  var arr = newJArray()
  for f in feats:
    arr.add(%f)
  %*{
    "iss": TestIss, "aud": TestAud, "license_hash": hash,
    "nonce": nonce, "status": status, "features": arr,
    "iat": now, "exp": now + 300
  }

proc statusQuery(jti, hash, nonce: string): StatusQuery =
  StatusQuery(jti: jti, licenseHash: hash, nonce: nonce,
    features: @["export"])

proc randomSeed(): array[32, byte] =
  let raw = urandom(32)
  for i in 0 ..< 32:
    result[i] = raw[i]

proc portBusy(): bool =
  var sock = newSocket()
  try:
    sock.connect("127.0.0.1", Port(RedPort), timeout = 300)
    true
  except CatchableError:
    false
  finally:
    try: sock.close()
    except CatchableError: discard

var redProcs: seq[Process] = @[]

proc killRed() =
  for p in redProcs:
    try:
      p.kill()
      discard p.waitForExit(2000)
    except CatchableError:
      discard
    try: p.close()
    except CatchableError: discard
  redProcs = @[]

proc startBin(bin: string, args: seq[string]): bool =
  if not fileExists(bin):
    return false
  killRed()
  try:
    redProcs.add(startProcess(bin, args = args,
      options = {poStdErrToStdOut, poUsePath}))
  except CatchableError:
    return false
  for _ in 0 ..< 30:
    if portBusy():
      return true
    sleep(100)
  killRed()
  false

suite "redteam: token forgery stays offline-blocked (R2t)":
  test "R2t fresh random key is denied":
    let rp = jwkOkpFromSeed(randomSeed(), "hacker-key")
    let tok = jwsSign(EdDSA, rp, """{"iss":"your-company","aud":"your-product","sub":"x","iat":1760000000,"exp":1762592000,"jti":"forged-1","plan":"pro","customer_id":"c","binding":{"type":"none"}}""")
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st != valid
    check st == unknownKey

  test "R2t random key with spoofed kid is denied":
    let rp = jwkOkpFromSeed(randomSeed(), "hacker-key")
    let forged = jwsSign(EdDSA, rp, """{"iss":"your-company","aud":"your-product","sub":"x","iat":1760000000,"exp":1762592000,"jti":"forged-2","plan":"pro","customer_id":"c","binding":{"type":"none"}}""")
    let parts = forged.split('.')
    let spoofed = b64urlEncode($ %*{"alg": "EdDSA", "kid": TestKid}) &
      "." & parts[1] & "." & parts[2]
    let (st, _) = validateLicenseOffline(spoofed, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st != valid

  test "R2t alg none header is denied":
    let tok = mintRevoked()
    let parts = tok.split('.')
    let noneHdr = b64urlEncode($ %*{"alg": "none"})
    let (st, _) = validateLicenseOffline(
      noneHdr & "." & parts[1] & "." & parts[2],
      trusted(), TestIss, TestAud, BaseNow + 100)
    check st != valid

suite "redteam: reply binding without any server (R4/R5/R6)":
  test "R4 replayed reply with wrong nonce is rejected":
    let body = signStatus(
      statusPayload("nonce-A", "hash-A", "valid", BaseNow + 100))
    check verifyStatusReply(body, statusQuery("lic", "hash-A", "nonce-B"),
      trusted(), TestIss, TestAud, BaseNow + 100) == onlineUnavailable

  test "R5 valid reply for a different license is rejected":
    let body = signStatus(
      statusPayload("n-1", "hash-A", "valid", BaseNow + 100))
    check verifyStatusReply(body, statusQuery("lic", "hash-B", "n-1"),
      trusted(), TestIss, TestAud, BaseNow + 100) == onlineUnavailable

  test "R6 reply signed with unknown key is rejected":
    let rk = jwkOkpFromSeed(randomSeed(), "hacker-status-key")
    let body = signStatus(
      statusPayload("n-1", "hash-A", "valid", BaseNow + 100), rk)
    check verifyStatusReply(body, statusQuery("lic", "hash-A", "n-1"),
      trusted(), TestIss, TestAud, BaseNow + 100) == onlineUnavailable

  test "R6 reply under retired kid is rejected":
    let old = jwkOkpFromSeed(testSeed(), "retired-key-2025")
    let body = signStatus(
      statusPayload("n-1", "hash-A", "valid", BaseNow + 100), old)
    check verifyStatusReply(body, statusQuery("lic", "hash-A", "n-1"),
      trusted(), TestIss, TestAud, BaseNow + 100) == onlineUnavailable

suite "redteam: endpoint takeover on the same address":
  test "R1 unsigned forgery never yields a positive verdict":
    if not fileExists("./mock_server") or
        not fileExists("./hacker_server"):
      echo "server binaries missing, skipping R1"
      check true
    else:
      let now = getTime().toUnix()
      check startBin("./mock_server",
        @["--port:" & $RedPort, "--seed:tools/revocations.json"])
      let tok = mintRevoked(now - 100)
      var policy = defaultOnlinePolicy("http://127.0.0.1:" & $RedPort)
      let base = validateLicense(tok, trusted(), TestIss, TestAud,
        now, some(httpOnlineChecker(policy, trusted(), TestIss,
          TestAud)), policy)
      check base.online == onlineRevoked
      check not isAccepted(base, policy)
      # Takeover: same address, hostile server.
      check startBin("./hacker_server",
        @["--port:" & $RedPort, "--mode:always-valid"])
      let hacked = validateLicense(tok, trusted(), TestIss, TestAud,
        now, some(httpOnlineChecker(policy, trusted(), TestIss,
          TestAud)), policy)
      check hacked.online == onlineUnavailable
      check hacked.online != onlineValid
      check isAccepted(hacked, policy) # fail-open: no positive signal
      var strict = policy
      strict.requireOnline = true
      strict.allowUnavailable = false
      let denied = validateLicense(tok, trusted(), TestIss, TestAud,
        now, some(httpOnlineChecker(strict, trusted(), TestIss,
          TestAud)), strict)
      check denied.online == onlineUnavailable
      check not isAccepted(denied, strict)
      killRed()

  test "R2 forged-signed reply is rejected live":
    if not fileExists("./hacker_server"):
      echo "hacker binary missing, skipping R2"
      check true
    else:
      check startBin("./hacker_server",
        @["--port:" & $RedPort, "--mode:forged-signed"])
      var policy = defaultOnlinePolicy("http://127.0.0.1:" & $RedPort)
      policy.timeoutMs = 2000
      let checker = httpOnlineChecker(policy, trusted(), TestIss,
        TestAud)
      check checker(statusQuery("any-jti", repeat('a', 64),
        freshNonce())) == onlineUnavailable
      killRed()

  test "R3 chaos maps to onlineUnavailable":
    if not fileExists("./hacker_server"):
      echo "hacker binary missing, skipping R3"
      check true
    else:
      check startBin("./hacker_server",
        @["--port:" & $RedPort, "--mode:chaos"])
      var fast = defaultOnlinePolicy("http://127.0.0.1:" & $RedPort)
      fast.timeoutMs = 2000
      let checker = httpOnlineChecker(fast, trusted(), TestIss, TestAud)
      check checker(statusQuery("chaos-garbage", repeat('g', 64),
        freshNonce())) == onlineUnavailable
      check checker(statusQuery("chaos-big", repeat('b', 64),
        freshNonce())) == onlineUnavailable
      var drip = defaultOnlinePolicy("http://127.0.0.1:" & $RedPort)
      drip.timeoutMs = 500
      let dripChecker = httpOnlineChecker(drip, trusted(), TestIss,
        TestAud)
      check dripChecker(statusQuery("chaos-drip", repeat('d', 64),
        freshNonce())) == onlineUnavailable
      killRed()

  test "R0 blackhole follows policy both ways":
    killRed()
    sleep(300)
    if portBusy():
      echo "port still busy, skipping R0"
      check true
    else:
      var open = defaultOnlinePolicy("http://127.0.0.1:" & $RedPort)
      open.timeoutMs = 500
      let checker = httpOnlineChecker(open, trusted(), TestIss, TestAud)
      let q = statusQuery("any-jti", repeat('a', 64), "n")
      check checker(q) == onlineUnavailable
      var strict = open
      strict.requireOnline = true
      strict.allowUnavailable = false
      let res = CombinedResult(offline: valid, online: onlineUnavailable,
        license: License())
      check isAccepted(res, open)
      check not isAccepted(res, strict)
