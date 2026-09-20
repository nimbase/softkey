# Example integration tests: the premium_cli demo keys and policies,
# exercised through the softkey library. Deterministic: every test
# injects `now`; no live server required (stub checkers + crafted
# reply JWSs), except one localhost stall-server thread for the
# timeout case.
# Run with: clue test

import std/json
import std/net
import std/options
import std/os
import std/strutils
import std/times
import unittest

import jose
import softkey
import dev_keys

const
  BaseNow = 1770000000'i64
  Day = 24 * 3600

proc licenseKeys(): seq[TrustedKey] =
  @[TrustedKey(kid: DemoLicenseKid, pubkey: DemoLicensePubkey)]

proc onlineKeys(): seq[TrustedKey] =
  @[TrustedKey(kid: DemoOnlineKid, pubkey: DemoOnlinePubkey)]

proc licensePriv(): Jwk =
  jwkOkpFromSeed(demoLicenseSeed(), DemoLicenseKid)

proc onlinePriv(): Jwk =
  jwkOkpFromSeed(demoOnlineSeed(), DemoOnlineKid)

proc basePayload(): JsonNode =
  %*{
    "iss": DemoIss,
    "aud": DemoAud,
    "sub": "license-001",
    "jti": "license-001",
    "iat": BaseNow,
    "nbf": BaseNow,
    "exp": BaseNow + 30 * Day,
    "plan": "demo",
    "features": ["run"],
    "customer_id": "example-customer"
  }

proc mint(payload: JsonNode, key: Jwk): string =
  jwsSign(EdDSA, key, $payload)

proc tamperSeg(token: string, seg: int): string =
  var parts = token.split('.')
  var s = parts[seg]
  s[0] = if s[0] == 'A': 'B' else: 'A'
  parts[seg] = s
  parts.join(".")

proc queryFor(token: string, nonce = "test-nonce"): StatusQuery =
  let (_, lic) = validateLicenseOffline(token, licenseKeys(), DemoIss,
    DemoAud, BaseNow)
  StatusQuery(jti: lic.id, licenseHash: licenseHashOf(token),
    nonce: nonce, features: lic.features)

proc signedReply(q: StatusQuery, status: string,
    nonce = "", hash = "", key = none(Jwk),
    features = @["run"], iat = BaseNow,
    exp = BaseNow + 300): string =
  let k = if key.isSome: key.get() else: onlinePriv()
  let payload = %*{
    "iss": DemoIss,
    "aud": DemoOnlineAud,
    "license_hash": if hash.len > 0: hash else: q.licenseHash,
    "nonce": if nonce.len > 0: nonce else: q.nonce,
    "status": status,
    "features": %features,
    "iat": iat,
    "exp": exp
  }
  jwsSign(EdDSA, k, $payload)

proc stubChecker(s: OnlineStatus): OnlineChecker =
  result = proc(q: StatusQuery): OnlineStatus {.closure.} = s

suite "example offline validation":
  test "1. valid offline license succeeds":
    let tok = mint(basePayload(), licensePriv())
    let (st, lic) = validateLicenseOffline(tok, licenseKeys(), DemoIss,
      DemoAud, BaseNow)
    check st == valid
    check lic.plan == "demo"
    check lic.features == @["run"]

  test "2. tampered payload fails":
    let tok = tamperSeg(mint(basePayload(), licensePriv()), 1)
    let (st, _) = validateLicenseOffline(tok, licenseKeys(), DemoIss,
      DemoAud, BaseNow)
    check st == badSignature

  test "3. tampered signature fails":
    let tok = tamperSeg(mint(basePayload(), licensePriv()), 2)
    let (st, _) = validateLicenseOffline(tok, licenseKeys(), DemoIss,
      DemoAud, BaseNow)
    check st == badSignature

  test "4. unknown kid fails":
    var seed: array[32, byte]
    for i in 0 ..< 32:
      seed[i] = byte(77)
    let tok = mint(basePayload(), jwkOkpFromSeed(seed, "stranger-key"))
    let (st, _) = validateLicenseOffline(tok, licenseKeys(), DemoIss,
      DemoAud, BaseNow)
    check st == unknownKey

  test "5. wrong algorithm fails":
    let hdr = b64urlEncode(
      """{"alg":"HS256","typ":"JWT","kid":"""" & DemoLicenseKid & """"}""")
    let tok = hdr & "." & b64urlEncode($basePayload()) & "." &
      b64urlEncode("fakesig")
    let (st, _) = validateLicenseOffline(tok, licenseKeys(), DemoIss,
      DemoAud, BaseNow)
    check st == wrongAlgorithm

  test "6. expired license fails":
    var p = basePayload()
    p["iat"] = % (BaseNow - 40 * Day)
    p["nbf"] = % (BaseNow - 40 * Day)
    p["exp"] = % (BaseNow - 10 * Day)
    let (st, _) = validateLicenseOffline(mint(p, licensePriv()),
      licenseKeys(), DemoIss, DemoAud, BaseNow)
    check st == expired

  test "7. nbf in the future fails":
    var p = basePayload()
    p["nbf"] = % (BaseNow + 3600)
    let (st, _) = validateLicenseOffline(mint(p, licensePriv()),
      licenseKeys(), DemoIss, DemoAud, BaseNow)
    check st == notYetValid

  test "8. lifetime longer than 90 days fails":
    var p = basePayload()
    p["exp"] = % (BaseNow + 91 * Day)
    let (st, _) = validateLicenseOffline(mint(p, licensePriv()),
      licenseKeys(), DemoIss, DemoAud, BaseNow)
    check st == lifetimeTooLong

  test "9. wrong issuer fails":
    var p = basePayload()
    p["iss"] = %"someone-else"
    let (st, _) = validateLicenseOffline(mint(p, licensePriv()),
      licenseKeys(), DemoIss, DemoAud, BaseNow)
    check st == wrongIssuer

  test "10. wrong audience fails":
    var p = basePayload()
    p["aud"] = %"another-product"
    let (st, _) = validateLicenseOffline(mint(p, licensePriv()),
      licenseKeys(), DemoIss, DemoAud, BaseNow)
    check st == wrongAudience

  test "11. missing required claim fails":
    var p = basePayload()
    p.delete("customer_id")
    let (st, _) = validateLicenseOffline(mint(p, licensePriv()),
      licenseKeys(), DemoIss, DemoAud, BaseNow)
    check st == malformed

suite "example online verification":
  test "control: well-formed signed reply verifies":
    let tok = mint(basePayload(), licensePriv())
    let q = queryFor(tok)
    check verifyStatusReply(signedReply(q, "valid"), q, onlineKeys(),
      DemoIss, DemoOnlineAud, BaseNow) == onlineValid

  test "12. fake unsigned online response fails":
    let tok = mint(basePayload(), licensePriv())
    let q = queryFor(tok)
    check verifyStatusReply("""{"status":"valid"}""", q, onlineKeys(),
      DemoIss, DemoOnlineAud, BaseNow) == onlineUnavailable

  test "13. random-key online response fails":
    let tok = mint(basePayload(), licensePriv())
    let q = queryFor(tok)
    var seed: array[32, byte]
    for i in 0 ..< 32:
      seed[i] = byte(99)
    let bad = jwkOkpFromSeed(seed, DemoOnlineKid)
    check verifyStatusReply(signedReply(q, "valid", key = some(bad)), q,
      onlineKeys(), DemoIss, DemoOnlineAud, BaseNow) ==
      onlineUnavailable

  test "14. online response with wrong nonce fails":
    let tok = mint(basePayload(), licensePriv())
    let q = queryFor(tok)
    check verifyStatusReply(signedReply(q, "valid",
      nonce = "wrong-nonce"), q, onlineKeys(), DemoIss, DemoOnlineAud,
      BaseNow) == onlineUnavailable

  test "15. online response for another license fails":
    let tok = mint(basePayload(), licensePriv())
    let q = queryFor(tok)
    check verifyStatusReply(signedReply(q, "valid",
      hash = "0000000000000000000000000000000000000000000000000000000000000000"),
      q, onlineKeys(), DemoIss, DemoOnlineAud,
      BaseNow) == onlineUnavailable

  test "16. replayed response with a new nonce fails":
    let tok = mint(basePayload(), licensePriv())
    let old = queryFor(tok, "nonce-one")
    let body = signedReply(old, "valid")
    let fresh = queryFor(tok, "nonce-two")
    check verifyStatusReply(body, fresh, onlineKeys(), DemoIss,
      DemoOnlineAud, BaseNow) == onlineUnavailable

  test "17. signed revoked response denies execution":
    let tok = mint(basePayload(), licensePriv())
    let res = validateLicense(tok, licenseKeys(), DemoIss, DemoAud,
      BaseNow, some(stubChecker(onlineRevoked)))
    check res.online == onlineRevoked
    check res.offline == revoked
    check not isAccepted(res)

  test "19. offline fallback works only when explicitly enabled":
    let tok = mint(basePayload(), licensePriv())
    let res = validateLicense(tok, licenseKeys(), DemoIss, DemoAud,
      BaseNow, some(stubChecker(onlineUnavailable)))
    check isAccepted(res) # default fail-open
    var strict = defaultOnlinePolicy("http://127.0.0.1:9")
    strict.allowUnavailable = false
    strict.requireOnline = true
    check not isAccepted(res, strict)

  test "20. malformed or oversized response does not crash":
    let tok = mint(basePayload(), licensePriv())
    let q = queryFor(tok)
    check verifyStatusReply("", q, onlineKeys(), DemoIss,
      DemoOnlineAud, BaseNow) == onlineUnavailable
    check verifyStatusReply("not.a.token", q, onlineKeys(), DemoIss,
      DemoOnlineAud, BaseNow) == onlineUnavailable
    check verifyStatusReply("x".repeat(20000), q, onlineKeys(), DemoIss,
      DemoOnlineAud, BaseNow) == onlineUnavailable
    check verifyStatusReply(signedReply(q, "valid", features = @["run",
      "admin"]), q, onlineKeys(), DemoIss, DemoOnlineAud,
      BaseNow) == onlineUnavailable # widened features rejected

var stallReady = false

proc stallServer(port: Port) {.thread.} =
  var server = newSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(port, "127.0.0.1")
  server.listen()
  stallReady = true
  var client = newSocket()
  try:
    server.accept(client)
    sleep(8000) # stall past any client timeout
  except CatchableError:
    discard
  try: client.close()
  except CatchableError: discard
  try: server.close()
  except CatchableError: discard

suite "example generated keys":
  test "fresh jwkEd25519Generate keys validate end to end":
    let licKey = jwkEd25519Generate(DemoLicenseKid)
    let onlKey = jwkEd25519Generate(DemoOnlineKid)
    check licKey.okpPub != onlKey.okpPub
    # Seed round-trip (the mint/mock file flow): reimporting the seed
    # must reproduce the same public key.
    check jwkOkpFromSeed(licKey.okpSeed, DemoLicenseKid).okpPub ==
      licKey.okpPub
    let keys = @[TrustedKey(kid: DemoLicenseKid,
      pubkey: licKey.okpPub)]
    let okeys = @[TrustedKey(kid: DemoOnlineKid,
      pubkey: onlKey.okpPub)]
    let tok = mint(basePayload(), licKey)
    let (st, lic) = validateLicenseOffline(tok, keys, DemoIss,
      DemoAud, BaseNow)
    check st == valid
    let q = StatusQuery(jti: lic.id, licenseHash: licenseHashOf(tok),
      nonce: "gen-nonce", features: lic.features)
    let payload = %*{
      "iss": DemoIss,
      "aud": DemoOnlineAud,
      "license_hash": q.licenseHash,
      "nonce": q.nonce,
      "status": "valid",
      "features": ["run"],
      "iat": BaseNow,
      "exp": BaseNow + 300
    }
    check verifyStatusReply(jwsSign(EdDSA, onlKey, $payload), q, okeys,
      DemoIss, DemoOnlineAud, BaseNow) == onlineValid

suite "example network timeout":
  test "18. network timeout returns promptly":
    var thr: Thread[Port]
    createThread(thr, stallServer, Port(18181))
    var spins = 0
    while not stallReady and spins < 100:
      sleep(50)
      inc spins
    require stallReady
    var policy = defaultOnlinePolicy("http://127.0.0.1:18181")
    policy.timeoutMs = 400
    let checker = httpOnlineChecker(policy, onlineKeys(), DemoIss,
      DemoOnlineAud)
    let tok = mint(basePayload(), licensePriv())
    let t0 = getTime()
    let st = checker(StatusQuery(jti: "license-001",
      licenseHash: licenseHashOf(tok), nonce: "timeout-probe",
      features: @["run"]))
    let elapsed = getTime() - t0
    check st == onlineUnavailable
    check elapsed < initDuration(seconds = 6)
    joinThread(thr)
