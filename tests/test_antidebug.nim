# Anti-debug gate tests. No real debugger is attached in CI; tracer
# presence is simulated with SOFTKEY_FORCE_DEBUG=1.
# Run with: clue test

import std/json
import std/options
import std/os
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

proc mintValid(): string =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  let payload = %*{
    "iss": TestIss,
    "aud": TestAud,
    "sub": "license-01J",
    "iat": BaseNow,
    "exp": BaseNow + 30 * 24 * 3600,
    "jti": "antidebug-001",
    "plan": "pro",
    "features": ["export"],
    "max_seats": 5,
    "customer_id": "c1",
    "binding": {"type": "none"}
  }
  jwsSign(EdDSA, priv, $payload)

suite "anti-debug gate":
  test "disabled policy never raises":
    putEnv("SOFTKEY_FORCE_DEBUG", "1")
    try:
      let tok = mintValid()
      let (st, _) = validateLicenseOffline(tok, trusted(), TestIss,
        TestAud, BaseNow + 100, AntiDebugOff)
      check st == valid
      let res = validateLicense(tok, trusted(), TestIss, TestAud,
        BaseNow + 100, none(OnlineChecker),
        defaultOnlinePolicy("http://127.0.0.1:9"), AntiDebugOff)
      check res.offline == valid
    finally:
      delEnv("SOFTKEY_FORCE_DEBUG")

  test "clean environment reports securityOk":
    putEnv("SOFTKEY_FORCE_CLEAN", "1")
    try:
      check checkRuntimeEnvironment() == securityOk
    finally:
      delEnv("SOFTKEY_FORCE_CLEAN")

  test "forced tracer reports debuggerDetected":
    putEnv("SOFTKEY_FORCE_DEBUG", "1")
    try:
      check checkRuntimeEnvironment() == debuggerDetected
    finally:
      delEnv("SOFTKEY_FORCE_DEBUG")

  when defined(softkeyNoAntidebug):
    test "dev bypass flag disables enforcement":
      putEnv("SOFTKEY_FORCE_DEBUG", "1")
      try:
        # Must not raise even with an enabled policy and forced tracer.
        enforceNoDebugger(defaultAntiDebugPolicy())
        check true
      finally:
        delEnv("SOFTKEY_FORCE_DEBUG")
  else:
    test "enabled policy raises before validation":
      putEnv("SOFTKEY_FORCE_DEBUG", "1")
      try:
        let tok = mintValid()
        var raised = false
        try:
          discard validateLicenseOffline(tok, trusted(), TestIss,
            TestAud, BaseNow + 100, defaultAntiDebugPolicy())
        except DebuggerDetected as err:
          raised = true
          check err.status == debuggerDetected
        check raised
      finally:
        delEnv("SOFTKEY_FORCE_DEBUG")

    test "enabled policy raises on combined path with bad token":
      # Gate runs before offline validation, so even a malformed
      # token raises rather than returning malformed.
      putEnv("SOFTKEY_FORCE_DEBUG", "1")
      try:
        var raised = false
        try:
          discard validateLicense("bad.token.here", trusted(), TestIss,
            TestAud, BaseNow + 100, none(OnlineChecker),
            defaultOnlinePolicy("http://127.0.0.1:9"),
            defaultAntiDebugPolicy())
        except DebuggerDetected:
          raised = true
        check raised
      finally:
        delEnv("SOFTKEY_FORCE_DEBUG")

    test "enforceNoDebugger is a no-op when disabled":
      putEnv("SOFTKEY_FORCE_DEBUG", "1")
      try:
        enforceNoDebugger(AntiDebugOff)
        check true
      finally:
        delEnv("SOFTKEY_FORCE_DEBUG")
