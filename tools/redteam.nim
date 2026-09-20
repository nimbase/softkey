# Red-team oracle: proves the attack table end to end, localhost only.
#
#   clue build tools/redteam.nim --out:redteam
#   ./redteam --port:18080
#
# Expectation key ("rejected" = never honored as a verdict; hostile
# input maps to onlineUnavailable and acceptance follows policy):
#   A   legit mock       -> revoked jti denied (baseline)
#   R1  unsigned forgery -> unavailable; fail-open accepts without a
#                           positive signal, requireOnline denies
#   R2  forged-signed    -> unavailable (unknown key / bad signature)
#   R3  chaos            -> unavailable (garbage/big/timeout)
#   R0  blackhole        -> unavailable, acceptance follows policy
#   R4  wrong nonce      -> unavailable (pure verify, dev seed)
#   R5  wrong license    -> unavailable (pure verify, dev seed)
#   R6  unknown key      -> unavailable (pure verify, dev seed)
#   R2t random-key tokens -> denied offline (no server needed)
#
# Prints a result table. Exit code is nonzero iff any outcome
# contradicts its expectation.
#
# NEVER point this at a production server. Localhost only.

import std/json
import std/net
import std/options
import std/os
import std/osproc
import std/parseopt
import std/strformat
import std/strutils
import std/sysrand
import std/times

import jose
import softkey

const
  TestKid = "license-signing-key-2026-01"
  TestIss = "your-company"
  TestAud = "your-product"
  RevokedJti = "revoked-license-001"

proc testSeed(): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = byte(i + 1)

proc trusted(): seq[TrustedKey] =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  @[TrustedKey(kid: TestKid, pubkey: priv.okpPub)]

proc devStatusKey(): Jwk =
  jwkOkpFromSeed(testSeed(), TestKid)

proc mintRevoked(now: int64): string =
  let priv = jwkOkpFromSeed(testSeed(), TestKid)
  let payload = %*{
    "iss": TestIss, "aud": TestAud, "sub": "license-01J",
    "iat": now, "exp": now + 30 * 24 * 3600,
    "jti": RevokedJti, "plan": "pro", "features": ["export"],
    "max_seats": 5, "customer_id": "c1",
    "binding": {"type": "none"}
  }
  jwsSign(EdDSA, priv, $payload)

proc signStatus(payload: JsonNode, key = devStatusKey()): string =
  jwsSign(EdDSA, key, $payload)

proc statusQuery(jti, hash, nonce: string): StatusQuery =
  StatusQuery(jti: jti, licenseHash: hash, nonce: nonce,
    features: @["export"])

proc reachable(port: int): bool =
  var sock = newSocket()
  try:
    sock.connect("127.0.0.1", Port(port), timeout = 500)
    true
  except CatchableError:
    false
  finally:
    try: sock.close()
    except CatchableError: discard

proc startServer(bin: string, args: seq[string]): Process =
  result = startProcess(bin, args = args,
    options = {poStdErrToStdOut, poUsePath})
  for _ in 0 ..< 30:
    if reachable(parseInt(args[0].split(':')[1])):
      return
    sleep(100)
  quit("server did not come up: " & bin & " " & args.join(" "), 1)

proc stopServer(p: Process) =
  if p == nil:
    return
  try:
    p.kill()
    discard p.waitForExit(2000)
  except CatchableError:
    discard
  try: p.close()
  except CatchableError: discard

type Row = tuple[id, attack, got, want, verdict: string]

var rows: seq[Row] = @[]
var surprises = 0

proc record(id, attack, got, want: string) =
  let ok = got == want
  if not ok:
    inc surprises
  rows.add((id, attack, got, want, if ok: "EXPECTED" else: "SURPRISE"))

proc main() =
  var port = 18080
  var mockBin = "./mock_server"
  var hackerBin = "./hacker_server"
  var seed = "tools/revocations.json"
  for kind, key, val in getopt():
    case key
    of "port": port = parseInt(val)
    of "mock-bin": mockBin = val
    of "hacker-bin": hackerBin = val
    of "seed": seed = val
    else: discard
  if not fileExists(mockBin):
    quit("mock binary missing: " & mockBin &
      " (clue build tools/mock_server.nim --out:mock_server)", 1)
  if not fileExists(hackerBin):
    quit("hacker binary missing: " & hackerBin &
      " (clue build tools/hacker_server.nim --out:hacker_server)", 1)

  let now = getTime().toUnix()
  let tok = mintRevoked(now - 100)
  var policy = defaultOnlinePolicy("http://127.0.0.1:" & $port)
  let checkerOf = proc(p: OnlinePolicy): OnlineChecker =
    httpOnlineChecker(p, trusted(), TestIss, TestAud)

  # Phase A: legit baseline, signed replies.
  var srv = startServer(mockBin,
    @["--port:" & $port, "--seed:" & seed])
  try:
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      now, some(checkerOf(policy)), policy)
    record("A", "legit baseline revokes",
      if res.online == onlineRevoked and not isAccepted(res, policy):
        "denied" else: "accepted", "denied")
  finally:
    stopServer(srv)
  sleep(300)

  # R1: takeover with unsigned forgery.
  srv = startServer(hackerBin,
    @["--port:" & $port, "--mode:always-valid"])
  try:
    let res = validateLicense(tok, trusted(), TestIss, TestAud,
      now, some(checkerOf(policy)), policy)
    record("R1a", "unsigned forgery, fail-open",
      $res.online & "/" &
        (if isAccepted(res, policy): "accepted" else: "denied"),
      $onlineUnavailable & "/accepted")
    var strict = policy
    strict.requireOnline = true
    strict.allowUnavailable = false
    let res2 = validateLicense(tok, trusted(), TestIss, TestAud,
      now, some(checkerOf(strict)), strict)
    record("R1b", "unsigned forgery, requireOnline",
      $res2.online & "/" &
        (if isAccepted(res2, strict): "accepted" else: "denied"),
      $onlineUnavailable & "/denied")
  finally:
    stopServer(srv)
  sleep(300)

  # R2: forged-signed mode.
  srv = startServer(hackerBin,
    @["--port:" & $port, "--mode:forged-signed"])
  try:
    let q = statusQuery("any-jti", repeat('a', 64), freshNonce())
    record("R2", "forged-signed reply",
      $checkerOf(policy)(q), $onlineUnavailable)
  finally:
    stopServer(srv)
  sleep(300)

  # R3: chaos modes.
  srv = startServer(hackerBin, @["--port:" & $port, "--mode:chaos"])
  try:
    var fast = policy
    fast.timeoutMs = 2000
    let cf = checkerOf(fast)
    record("R3a", "garbage body",
      $cf(statusQuery("chaos-garbage", repeat('g', 64), freshNonce())),
      $onlineUnavailable)
    record("R3b", "oversized body",
      $cf(statusQuery("chaos-big", repeat('b', 64), freshNonce())),
      $onlineUnavailable)
    var dripPolicy = policy
    dripPolicy.timeoutMs = 500
    record("R3c", "10s drip vs 500ms timeout",
      $checkerOf(dripPolicy)(statusQuery("chaos-drip", repeat('d', 64),
        freshNonce())), $onlineUnavailable)
  finally:
    stopServer(srv)
  sleep(300)

  # R0: blackhole, both policies.
  record("R0a", "blackhole, fail-open",
    $checkerOf(policy)(statusQuery("any-jti", repeat('a', 64), "n")),
    $onlineUnavailable)
  var strict = policy
  strict.requireOnline = true
  strict.allowUnavailable = false
  let openAcc = isAccepted(CombinedResult(offline: valid,
    online: onlineUnavailable, license: License()), policy)
  let strictAcc = isAccepted(CombinedResult(offline: valid,
    online: onlineUnavailable, license: License()), strict)
  record("R0b", "blackhole follows policy",
    (if openAcc: "accepted" else: "denied") & "/" &
      (if strictAcc: "accepted" else: "denied"),
    "accepted/denied")

  # R4/R5/R6: pure verify with dev seed, fixed clock.
  let t0 = 1760000100'i64
  let goodPayload = %*{
    "iss": TestIss, "aud": TestAud, "license_hash": "hash-A",
    "nonce": "nonce-A", "status": "valid", "features": ["export"],
    "iat": t0, "exp": t0 + 300
  }
  let good = signStatus(goodPayload)
  record("R4", "wrong nonce",
    $verifyStatusReply(good,
      statusQuery("lic", "hash-A", "nonce-B"), trusted(), TestIss,
      TestAud, t0), $onlineUnavailable)
  record("R5", "wrong license hash",
    $verifyStatusReply(good,
      statusQuery("lic", "hash-B", "nonce-A"), trusted(), TestIss,
      TestAud, t0), $onlineUnavailable)
  let raw = urandom(32)
  var rseed: array[32, byte]
  for i in 0 ..< 32:
    rseed[i] = raw[i]
  let rk = jwkOkpFromSeed(rseed, "hacker-status-key")
  record("R6a", "random-key signature",
    $verifyStatusReply(signStatus(goodPayload, rk),
      statusQuery("lic", "hash-A", "nonce-A"), trusted(), TestIss,
      TestAud, t0), $onlineUnavailable)
  let retired = jwkOkpFromSeed(testSeed(), "retired-key-2025")
  record("R6b", "retired kid",
    $verifyStatusReply(signStatus(goodPayload, retired),
      statusQuery("lic", "hash-A", "nonce-A"), trusted(), TestIss,
      TestAud, t0), $onlineUnavailable)
  record("R4+", "correct bindings verify",
    $verifyStatusReply(good,
      statusQuery("lic", "hash-A", "nonce-A"), trusted(), TestIss,
      TestAud, t0), $onlineValid)

  # R2t: random-key token forgery, offline only.
  let forged = jwsSign(EdDSA, rk, """{"iss":"your-company","aud":"your-product","sub":"x","iat":1760000000,"exp":1762592000,"jti":"forged-1","plan":"pro","customer_id":"c","binding":{"type":"none"}}""")
  let (st1, _) = validateLicenseOffline(forged, trusted(), TestIss,
    TestAud, 1760000100)
  record("R2t", "random-key token",
    if st1 == valid: "accepted" else: "denied", "denied")

  echo "ID   attack                          got                          want                         verdict"
  for r in rows:
    echo fmt"{r.id:<4} {r.attack:<30} {r.got:<28} {r.want:<28} {r.verdict}"
  if surprises > 0:
    quit(fmt"{surprises} surprise(s): behavior changed, investigate", 1)
  echo "redteam complete: all outcomes as expected"

when isMainModule:
  main()
