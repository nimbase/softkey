# Online verification tests: stub checkers (no network) + mock integration.
# Run with: clue test
# For integration: clue build tools/mock_server.nim --out:mock_server
# then leave it running on :18080, or the suite will try to start it.

import std/httpclient
import std/json
import std/net
import std/options
import std/os
import std/osproc
import std/strutils
import std/times
import unittest

import jose
import softkey

const
  TestKid = "license-signing-key-2026-01"
  TestIss = "your-company"
  TestAud = "your-product"
  BaseNow = 1760000000'i64
  MockPort = 18080

proc testSeed(): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = byte(i + 1)

proc trusted(): seq[TrustedKey] =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  @[TrustedKey(kid: TestKid, pubkey: priv.okpPub)]

proc mintWithJti(jti: string, now = BaseNow): string =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  let payload = %*{
    "iss": TestIss,
    "aud": TestAud,
    "sub": "license-01J",
    "iat": now,
    "exp": now + 30 * 24 * 3600,
    "jti": jti,
    "plan": "pro",
    "features": ["export"],
    "max_seats": 5,
    "customer_id": "c1",
    "binding": {"type": "none"}
  }
  jwsSign(EdDSA, priv, $payload)

proc someChecker(s: OnlineStatus): OnlineChecker =
  result = proc(q: StatusQuery): OnlineStatus {.closure.} = s

proc mockReachable(): bool =
  var sock = newSocket()
  try:
    sock.connect("127.0.0.1", Port(MockPort), timeout = 500)
    true
  except CatchableError:
    false
  finally:
    try: sock.close()
    except CatchableError: discard

var mockProc: Process

proc ensureMock(): bool =
  if mockReachable():
    return true
  for cand in ["./mock_server", "mock_server", "/tmp/mock_server_it"]:
    if fileExists(cand):
      try:
        mockProc = startProcess(cand,
          args = ["--port:" & $MockPort, "--seed:tools/revocations.json"],
          options = {poStdErrToStdOut, poUsePath})
        break
      except CatchableError:
        continue
  for _ in 0 ..< 20:
    if mockReachable():
      return true
    sleep(100)
  false

suite "online composition with stub checkers":
  test "revoked overrides valid offline":
    let tok = mintWithJti("lic-001")
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100, some(someChecker(onlineRevoked)))
    check res.offline == revoked
    check res.online == onlineRevoked
    check not isAccepted(res)

  test "online valid keeps offline valid":
    let tok = mintWithJti("lic-001")
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100, some(someChecker(onlineValid)))
    check res.offline == valid
    check res.online == onlineValid
    check isAccepted(res)

  test "unavailable fail-open keeps valid":
    let tok = mintWithJti("lic-001")
    let policy = defaultOnlinePolicy("http://127.0.0.1:9")
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100, some(someChecker(onlineUnavailable)), policy)
    check res.offline == valid
    check res.online == onlineUnavailable
    check isAccepted(res, policy)

  test "unavailable with requireOnline denies":
    let tok = mintWithJti("lic-001")
    var policy = defaultOnlinePolicy("http://127.0.0.1:9")
    policy.requireOnline = true
    policy.allowUnavailable = false
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100, some(someChecker(onlineUnavailable)), policy)
    check res.offline == valid
    check not isAccepted(res, policy)

  test "offline failure short-circuits without online":
    var called = false
    let checker: OnlineChecker =
      proc(q: StatusQuery): OnlineStatus {.closure.} =
        called = true
        onlineValid
    let res = validateLicense("bad.token.here", trusted(), TestIss,
      TestAud, BaseNow + 100, some(checker))
    check res.offline != valid
    check res.online == onlineNotChecked
    check not called
    check not isAccepted(res)

  test "no checker means offline only":
    let tok = mintWithJti("lic-001")
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100)
    check res.offline == valid
    check res.online == onlineNotChecked
    check isAccepted(res)

  test "renewalRequired surfaces but still accepted":
    let tok = mintWithJti("lic-001")
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100, some(someChecker(renewalRequired)))
    check res.offline == valid
    check res.online == renewalRequired
    check isAccepted(res)

  test "raising checker maps to unavailable":
    let checker: OnlineChecker =
      proc(q: StatusQuery): OnlineStatus {.closure.} =
        raise newException(ValueError, "boom")
    let tok = mintWithJti("lic-001")
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      BaseNow + 100, some(checker))
    check res.online == onlineUnavailable
    check isAccepted(res) # default fail-open

suite "mock server integration (signed replies)":
  test "revoked and valid jtis via httpOnlineChecker":
    if not ensureMock():
      echo "mock server not available, skipping integration"
      check true
    else:
      # Live clock: the mock signs replies with real now, so the
      # license token must be live too.
      let now = getTime().toUnix()
      var policy = defaultOnlinePolicy(
        "http://127.0.0.1:" & $MockPort)
      policy.timeoutMs = 2000
      let checker = httpOnlineChecker(policy, trusted(), TestIss,
        TestAud)
      let q = StatusQuery(jti: "revoked-license-001",
        licenseHash: repeat('c', 64), nonce: freshNonce(),
        features: @["export"])
      check checker(q) == onlineRevoked
      let q2 = StatusQuery(jti: "some-fresh-jti-xyz",
        licenseHash: repeat('f', 64), nonce: freshNonce(),
        features: @["export"])
      check checker(q2) == onlineValid
      let q3 = StatusQuery(jti: "renew-soon-001",
        licenseHash: repeat('b', 64), nonce: freshNonce(),
        features: @["export"])
      check checker(q3) == renewalRequired
      let tok = mintWithJti("revoked-license-001", now - 100)
      let res = validateLicense(tok, trusted(), TestIss, TestAud,
        now, some(checker), policy)
      check res.offline == revoked
      check not isAccepted(res, policy)

  test "closed port maps to unavailable":
    var policy = defaultOnlinePolicy("http://127.0.0.1:9")
    policy.timeoutMs = 500
    let checker = httpOnlineChecker(policy, trusted(), TestIss,
      TestAud)
    let q = StatusQuery(jti: "any-jti", licenseHash: repeat('a', 64),
      nonce: "n", features: @["export"])
    check checker(q) == onlineUnavailable
