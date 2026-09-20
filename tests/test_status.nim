# Signed status reply tests: pure verifyStatusReply matrix, no network.
# Run with: clue test
#
# The dev status key is the test license seed (bytes 1..32), same as
# tools/mock_server.nim. NEVER SHIP: production signs with the real
# license key from secure storage.

import std/json
import std/strutils
import std/sysrand
import unittest

import jose
import softkey

const
  TestKid = "license-signing-key-2026-01"
  TestIss = "your-company"
  TestAud = "your-product"
  BaseNow = 1760000000'i64
  MaxAge = 300'i64
  Leeway = 60'i64

proc testSeed(): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = byte(i + 1)

proc statusKey(): Jwk =
  jwkOkpFromSeed(testSeed(), TestKid)

proc trusted(): seq[TrustedKey] =
  @[TrustedKey(kid: TestKid, pubkey: statusKey().okpPub)]

proc baseReply(nonce, hash: string, status = "valid",
    iat = BaseNow, exp = BaseNow + 300): JsonNode =
  %*{
    "iss": TestIss,
    "aud": TestAud,
    "license_hash": hash,
    "nonce": nonce,
    "status": status,
    "features": ["export"],
    "iat": iat,
    "exp": exp
  }

proc signReply(payload: JsonNode, key = statusKey()): string =
  jwsSign(EdDSA, key, $payload)

proc query(nonce = "n-001", hash = "ab",
    feats = @["export", "batch-processing"]): StatusQuery =
  StatusQuery(jti: "lic-001", licenseHash: hash, nonce: nonce,
    features: feats)

proc checkReply(body: string, q = query()): OnlineStatus =
  verifyStatusReply(body, q, trusted(), TestIss, TestAud,
    BaseNow + 100, MaxAge, Leeway)

suite "signed status replies":
  test "valid reply verifies":
    check checkReply(signReply(baseReply("n-001", "ab"))) == onlineValid

  test "revoked and renewal map through":
    check checkReply(signReply(
      baseReply("n-001", "ab", "revoked"))) == onlineRevoked
    check checkReply(signReply(
      baseReply("n-001", "ab", "renewal_required"))) == renewalRequired

  test "unknown status string is unavailable":
    check checkReply(signReply(
      baseReply("n-001", "ab", "maybe"))) == onlineUnavailable

  test "unsigned body is unavailable":
    check checkReply($baseReply("n-001", "ab")) == onlineUnavailable
    check checkReply("a.b.c") == onlineUnavailable
    check checkReply("") == onlineUnavailable

  test "tampered payload is unavailable":
    var tok = signReply(baseReply("n-001", "ab"))
    let parts = tok.split('.')
    var payload = b64urlDecodeStr(parts[1]).replace("valid", "revoked")
    check checkReply(
      parts[0] & "." & b64urlEncode(payload) & "." & parts[2]
    ) == onlineUnavailable

  test "random-key signature is unavailable (R2/R6)":
    let raw = urandom(32)
    var seed: array[32, byte]
    for i in 0 ..< 32:
      seed[i] = raw[i]
    let rk = jwkOkpFromSeed(seed, "hacker-status-key")
    check checkReply(signReply(baseReply("n-001", "ab"), rk)
    ) == onlineUnavailable

  test "retired kid is unavailable (R6)":
    let other = jwkOkpFromSeed(testSeed(), "retired-key-2025")
    check checkReply(signReply(baseReply("n-001", "ab"), other)
    ) == onlineUnavailable

  test "wrong iss and aud are unavailable":
    var p = baseReply("n-001", "ab")
    p["iss"] = %"evil"
    check checkReply(signReply(p)) == onlineUnavailable
    p = baseReply("n-001", "ab")
    p["aud"] = %"other-product"
    check checkReply(signReply(p)) == onlineUnavailable

  test "wrong nonce is unavailable (R4)":
    check checkReply(signReply(baseReply("nonce-A", "ab")),
      query("nonce-B", "ab")) == onlineUnavailable

  test "wrong license hash is unavailable (R5)":
    check checkReply(signReply(baseReply("n-001", "hash-A")),
      query("n-001", "hash-B")) == onlineUnavailable

  test "float timestamps are unavailable":
    var p = baseReply("n-001", "ab")
    p["exp"] = % 1760000300.5
    check checkReply(signReply(p)) == onlineUnavailable

  test "stale and future windows are unavailable":
    check checkReply(signReply(
      baseReply("n-001", "ab", "valid", BaseNow - 1000, BaseNow - 700))
    ) == onlineUnavailable
    check checkReply(signReply(
      baseReply("n-001", "ab", "valid", BaseNow + 1000, BaseNow + 1300))
    ) == onlineUnavailable

  test "lifetime over cap is unavailable, cap exactly passes":
    check checkReply(signReply(
      baseReply("n-001", "ab", "valid", BaseNow, BaseNow + 3600))
    ) == onlineUnavailable
    check checkReply(signReply(
      baseReply("n-001", "ab", "valid", BaseNow + 100, BaseNow + 400))
    ) == onlineValid

  test "widened features rejected, narrowed accepted":
    var p = baseReply("n-001", "ab")
    p["features"] = %*["export", "admin"]
    check checkReply(signReply(p)) == onlineUnavailable
    p = baseReply("n-001", "ab")
    check checkReply(signReply(p)) == onlineValid
    p = baseReply("n-001", "ab")
    p.delete("features")
    check checkReply(signReply(p)) == onlineUnavailable

  test "missing status is unavailable":
    var p = baseReply("n-001", "ab")
    p.delete("status")
    check checkReply(signReply(p)) == onlineUnavailable

  test "oversized and wrong-alg bodies are unavailable":
    check checkReply("x".repeat(20000)) == onlineUnavailable
    let tok = signReply(baseReply("n-001", "ab"))
    let parts = tok.split('.')
    let hdr = b64urlEncode($ %*{"alg": "HS256", "kid": TestKid})
    check checkReply(
      hdr & "." & parts[1] & "." & parts[2]) == onlineUnavailable
