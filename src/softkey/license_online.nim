# Online license checks layered over deterministic offline validation.
#
# Offline runs first and alone decides cryptographic validity. The online
# step only adds revocation / renewal signals. Status replies are compact
# JWS (EdDSA) bound to the presented license and a fresh client nonce:
# bare {"status": ...} JSON is never honored.
#
# Reply contract (signed payload):
#   iss, aud, license_hash (sha256 hex of the compact license),
#   nonce (echo of the request nonce), status, features, iat, exp.
# Acceptance: valid signature, expected iss/aud, nonce and hash equal
# the request, status allowed, iat/exp inside the policy window,
# reply features subset of the license features. First failure maps to
# onlineUnavailable, never to onlineRevoked.

import std/httpclient
import std/json
import std/options
import std/strutils
import std/sysrand
import std/times

import jose
import nimcypher/hash as cyHash

import ./license_types
import ./license_verify
import ./antidebug

export license_types
export options

type
  OnlineChecker* = proc(q: StatusQuery): OnlineStatus {.closure.}

const StatusBodyCap = 16384

proc defaultPolicy(): OnlinePolicy =
  OnlinePolicy(baseUrl: "", timeoutMs: 2000, allowUnavailable: true,
    requireOnline: false, statusMaxAgeSec: 300, statusLeewaySec: 60)

proc parseOnlineStatus(s: string): OnlineStatus =
  case s.strip().toLowerAscii()
  of "valid": onlineValid
  of "revoked": onlineRevoked
  of "renewal_required", "renewalrequired", "renew": renewalRequired
  else: onlineUnavailable

proc payloadToStr(data: openArray[byte]): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(data[i])

proc licenseHashOf*(token: string): string =
  ## Lowercase hex SHA-256 over the exact compact license bytes.
  cyHash.sha256Hex(token).toLowerAscii()

proc freshNonce*(): string =
  ## base64url-no-pad of 32 fresh random bytes.
  b64urlEncode(urandom(32))

proc findStatusKey(keys: openArray[TrustedKey], kid: string): int =
  if kid.len == 0:
    if keys.len == 1:
      return 0
    return -1
  for i in 0 ..< keys.len:
    if keys[i].kid == kid:
      return i
  -1

proc verifyStatusReply*(
  body: string,
  query: StatusQuery,
  trustedKeys: openArray[TrustedKey],
  expectedIss: string,
  expectedAud: string,
  now: int64,
  maxAge = 300'i64,
  leeway = 60'i64
): OnlineStatus =
  ## Pure verification of one signed status reply. No I/O, no clock
  ## reads: every hostile input maps to onlineUnavailable.
  if body.len == 0 or body.len > StatusBodyCap:
    return onlineUnavailable
  let parts = body.split('.')
  if parts.len != 3 or parts[0].len == 0 or parts[1].len == 0 or
      parts[2].len == 0:
    return onlineUnavailable
  var hdr: JsonNode
  try:
    hdr = parseJson(b64urlDecodeStr(parts[0]))
  except JoseError, JsonParsingError, ValueError:
    return onlineUnavailable
  if hdr.kind != JObject or not hdr.hasKey("alg") or
      hdr["alg"].kind != JString or hdr["alg"].getStr() != "EdDSA":
    return onlineUnavailable
  var kid = ""
  if hdr.hasKey("kid"):
    if hdr["kid"].kind != JString:
      return onlineUnavailable
    kid = hdr["kid"].getStr()
  let keyIdx = findStatusKey(trustedKeys, kid)
  if keyIdx < 0:
    return onlineUnavailable
  let v =
    try:
      jwsVerify(body, jwkOkpFromPub(trustedKeys[keyIdx].pubkey,
        trustedKeys[keyIdx].kid), [EdDSA])
    except JoseError, ValueError:
      return onlineUnavailable
  let payloadStr = payloadToStr(v.payload)
  var claims: JsonNode
  try:
    claims = parseJson(payloadStr)
  except JsonParsingError, ValueError:
    return onlineUnavailable
  if claims.kind != JObject:
    return onlineUnavailable
  if not claims.hasKey("iss") or claims["iss"].kind != JString or
      claims["iss"].getStr() != expectedIss:
    return onlineUnavailable
  if not claims.hasKey("aud") or claims["aud"].kind != JString or
      claims["aud"].getStr() != expectedAud:
    return onlineUnavailable
  if not claims.hasKey("nonce") or claims["nonce"].kind != JString or
      claims["nonce"].getStr() != query.nonce:
    return onlineUnavailable
  if not claims.hasKey("license_hash") or
      claims["license_hash"].kind != JString or
      claims["license_hash"].getStr() != query.licenseHash:
    return onlineUnavailable
  if not claims.hasKey("status") or claims["status"].kind != JString:
    return onlineUnavailable
  let st = parseOnlineStatus(claims["status"].getStr())
  if st == onlineUnavailable or st == onlineNotChecked:
    return onlineUnavailable
  if not claims.hasKey("iat") or claims["iat"].kind != JInt or
      not claims.hasKey("exp") or claims["exp"].kind != JInt:
    return onlineUnavailable
  let iat = claims["iat"].getInt()
  let exp = claims["exp"].getInt()
  if iat > now + leeway or exp <= iat or exp - iat > maxAge or
      now > exp + leeway:
    return onlineUnavailable
  # Enforced features: the reply may narrow, never widen.
  if not claims.hasKey("features") or claims["features"].kind != JArray:
    return onlineUnavailable
  for item in claims["features"]:
    if item.kind != JString or item.getStr() notin query.features:
      return onlineUnavailable
  st

proc httpOnlineChecker*(
  policy: OnlinePolicy,
  trustedKeys: seq[TrustedKey],
  expectedIss: string,
  expectedAud: string
): OnlineChecker =
  ## Build an OnlineChecker that POSTs {jti, license_hash, nonce} to
  ## {baseUrl}/v1/licenses/verify and verifies the signed reply.
  ## Unsigned, stale, replayed, or widened replies map to
  ## onlineUnavailable. now/keys/iss/aud are captured per call site;
  ## the nonce is fresh per request.
  let base = policy.baseUrl.strip(chars = {'/'})
  let timeout = policy.timeoutMs
  let maxAge = policy.statusMaxAgeSec
  let leeway = policy.statusLeewaySec
  result = proc(q: StatusQuery): OnlineStatus {.closure.} =
    if q.jti.len == 0 or q.jti.len > 256 or q.nonce.len == 0 or
        q.licenseHash.len != 64:
      return onlineUnavailable
    var client = newHttpClient(timeout = timeout)
    try:
      client.headers = newHttpHeaders({
        "Authorization": "Bearer mock-dev-token",
        "Content-Type": "application/json"})
      let req = $(%*{"jti": q.jti, "license_hash": q.licenseHash,
        "nonce": q.nonce})
      let body = client.postContent(base & "/v1/licenses/verify", req)
      verifyStatusReply(body, q, trustedKeys, expectedIss, expectedAud,
        getTime().toUnix(), maxAge, leeway)
    except CatchableError:
      onlineUnavailable
    finally:
      try: client.close()
      except CatchableError: discard

proc checkLicenseOnline*(q: StatusQuery, checker: OnlineChecker): OnlineStatus =
  if checker.isNil:
    return onlineNotChecked
  try:
    checker(q)
  except CatchableError:
    onlineUnavailable

proc validateLicense*(
  token: string,
  trustedKeys: openArray[TrustedKey],
  expectedIss: string,
  expectedAud: string,
  now: int64,
  checker: Option[OnlineChecker] = none(OnlineChecker),
  policy: OnlinePolicy = OnlinePolicy(baseUrl: "", timeoutMs: 2000,
    allowUnavailable: true, requireOnline: false,
    statusMaxAgeSec: 300, statusLeewaySec: 60),
  antidebug: AntiDebugPolicy = AntiDebugOff
): CombinedResult =
  ## Anti-debug gate first (raises DebuggerDetected), then offline,
  ## then online only if offline is valid. The online query binds the
  ## exact token hash and a fresh nonce.
  enforceNoDebugger(antidebug)
  let (offStatus, lic) = validateLicenseOffline(token, trustedKeys,
    expectedIss, expectedAud, now)
  if offStatus != valid:
    return CombinedResult(offline: offStatus, online: onlineNotChecked,
      license: lic)
  if checker.isNone or checker.get().isNil:
    return CombinedResult(offline: valid, online: onlineNotChecked,
      license: lic)
  let q = StatusQuery(jti: lic.id, licenseHash: licenseHashOf(token),
    nonce: freshNonce(), features: lic.features)
  let onStatus =
    try: checker.get()(q)
    except CatchableError: onlineUnavailable
  case onStatus
  of onlineRevoked:
    CombinedResult(offline: revoked, online: onlineRevoked, license: lic)
  of renewalRequired:
    CombinedResult(offline: valid, online: renewalRequired, license: lic)
  of onlineValid:
    CombinedResult(offline: valid, online: onlineValid, license: lic)
  of onlineUnavailable, onlineNotChecked:
    # Report truthfully; denial is decided by isAccepted(), not by
    # rewriting the offline result.
    CombinedResult(offline: valid, online: onStatus, license: lic)

proc isAccepted*(res: CombinedResult,
    policy: OnlinePolicy = OnlinePolicy(baseUrl: "", timeoutMs: 2000,
    allowUnavailable: true, requireOnline: false,
    statusMaxAgeSec: 300, statusLeewaySec: 60)): bool =
  ## Deny unless offline is valid. A revoked online check always denies.
  ## Unavailable denies only when requireOnline or not allowUnavailable.
  if res.offline != valid:
    return false
  case res.online
  of onlineNotChecked, onlineValid, renewalRequired:
    true
  of onlineRevoked:
    false
  of onlineUnavailable:
    policy.allowUnavailable and not policy.requireOnline

proc validateLicense*(
  token: string,
  trustedKeys: openArray[TrustedKey],
  expectedIss: string,
  expectedAud: string,
  checker: Option[OnlineChecker] = none(OnlineChecker),
  policy: OnlinePolicy = OnlinePolicy(baseUrl: "", timeoutMs: 2000,
    allowUnavailable: true, requireOnline: false,
    statusMaxAgeSec: 300, statusLeewaySec: 60),
  antidebug: AntiDebugPolicy = AntiDebugOff
): CombinedResult =
  ## Convenience overload using the system clock.
  validateLicense(token, trustedKeys, expectedIss, expectedAud,
    getTime().toUnix(), checker, policy, antidebug)
