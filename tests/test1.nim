# Offline license validation tests (Phase 1, no network).
# Run with: clue test

import std/json
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

proc testSeed(): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = byte(i + 1)

proc trusted(): seq[TrustedKey] =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  @[TrustedKey(kid: TestKid, pubkey: priv.okpPub)]

proc mint(payload: JsonNode, kid = TestKid): string =
  let priv = jwkOkpFromSeed(testSeed(), kid)
  jwsSign(EdDSA, priv, $payload)

proc basePayload(expOff = 30 * 24 * 3600, iatOff = 0'i64): JsonNode =
  %*{
    "iss": TestIss,
    "aud": TestAud,
    "sub": "license-01J",
    "iat": BaseNow + iatOff,
    "exp": BaseNow + iatOff + expOff,
    "jti": "unique-license-token-id",
    "plan": "pro",
    "features": ["export", "batch-processing"],
    "max_seats": 5,
    "customer_id": "opaque-customer-id",
    "binding": {"type": "none"}
  }

suite "offline license validation":
  test "valid token verifies and exposes claims":
    let tok = mint(basePayload())
    let (st, lic) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == valid
    check lic.id == "unique-license-token-id"
    check lic.plan == "pro"
    check lic.features == @["export", "batch-processing"]
    check lic.maxSeats == 5
    check lic.customerId == "opaque-customer-id"
    check lic.expiresAt == BaseNow + 30 * 24 * 3600

  test "tampered payload is badSignature":
    var tok = mint(basePayload())
    let parts = tok.split('.')
    var payload = b64urlDecodeStr(parts[1])
    payload = payload.replace("pro", "ent")
    tok = parts[0] & "." & b64urlEncode(payload) & "." & parts[2]
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == badSignature

  test "wrong alg header is wrongAlgorithm":
    var tok = mint(basePayload())
    let parts = tok.split('.')
    let hdr = %*{"alg": "HS256", "kid": TestKid}
    tok = b64urlEncode($hdr) & "." & parts[1] & "." & parts[2]
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == wrongAlgorithm

  test "unknown kid is unknownKey":
    let tok = mint(basePayload(), kid = "unknown-kid")
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == unknownKey

  test "wrong issuer and audience":
    let tok = mint(basePayload())
    let (s1, _) = validateLicenseOffline(tok, trusted(), "other",
      TestAud, BaseNow + 100)
    check s1 == wrongIssuer
    let (s2, _) = validateLicenseOffline(tok, trusted(), TestIss,
      "other-product", BaseNow + 100)
    check s2 == wrongAudience

  test "expired token":
    let tok = mint(basePayload())
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 31 * 24 * 3600)
    check st == expired

  test "future iat is notYetValid":
    let tok = mint(basePayload(iatOff = 3600))
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow)
    check st == notYetValid

  test "nbf in future is notYetValid":
    var p = basePayload()
    p["nbf"] = % (BaseNow + 3600)
    let tok = mint(p)
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow)
    check st == notYetValid

  test "lifetime over 90 days is lifetimeTooLong":
    let tok = mint(basePayload(expOff = 91 * 24 * 3600))
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == lifetimeTooLong

  test "exactly 90 days passes":
    let tok = mint(basePayload(expOff = 90 * 24 * 3600))
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == valid

  test "malformed shapes":
    let (s1, _) = validateLicenseOffline("abc", trusted(), TestIss,
      TestAud, BaseNow)
    check s1 == malformed
    let (s2, _) = validateLicenseOffline("a.b.c.d", trusted(), TestIss,
      TestAud, BaseNow)
    check s2 == malformed

  test "duplicate JSON members rejected":
    let priv = jwkOkpFromSeed(testSeed(), TestKid)
    let dupPayload = """{"iss":"your-company","aud":"your-product","sub":"license-01J","iat":1760000000,"exp":1762592000,"jti":"unique-license-token-id","plan":"pro","plan":"pro","features":["export"],"max_seats":5,"customer_id":"opaque-customer-id","binding":{"type":"none"}}"""
    let tok = jwsSign(EdDSA, priv, dupPayload)
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == malformed

  test "float timestamps rejected":
    var p = basePayload()
    p["exp"] = % 1760000000.5
    # Build raw JSON with float exp, then sign.
    let tok = mint(p)
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == malformed

  test "unsupported binding":
    var p = basePayload()
    p["binding"] = %*{"type": "ed25519", "key_id": "d1",
      "pubkey_hash": "00"}
    let tok = mint(p)
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == unsupportedBinding

  test "array aud accepted":
    var p = basePayload()
    p["aud"] = %*["other", TestAud]
    let tok = mint(p)
    let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
      TestAud, BaseNow + 100)
    check st == valid
