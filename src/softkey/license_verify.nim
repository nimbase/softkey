# Offline license verification: compact JWS + EdDSA, strict profile.
#
# Order: anti-debug gate (opt-in, raises) -> shape gate -> header
# allowlist -> kid lookup -> signature verify -> payload parse ->
# claim + lifetime + binding checks.
# No claims are exposed until every check passes.

import std/json
import std/strutils
import std/times

import jose

import ./license_types
import ./antidebug

export license_types

proc payloadToStr(data: openArray[byte]): string =
  result = newString(data.len)
  for i in 0 ..< data.len:
    result[i] = char(data[i])

proc findTrustedKey(keys: openArray[TrustedKey], kid: string): int =
  ## Returns index or -1. Empty kid matches only a singleton set.
  if kid.len == 0:
    if keys.len == 1:
      return 0
    return -1
  for i in 0 ..< keys.len:
    if keys[i].kid == kid:
      return i
  -1

proc hasDuplicateTopLevelKeys(payload: string): bool =
  ## Minimal scanner rejecting duplicate top-level object member names.
  ## Operates on the raw JSON text so std/json's last-wins behavior
  ## cannot hide duplicates.
  var i = 0
  let n = payload.len
  proc skipWs() =
    while i < n and payload[i] in {' ', '\t', '\n', '\r'}:
      inc i
  skipWs()
  if i >= n or payload[i] != '{':
    return false # not our problem here; caller reports malformed
  inc i
  var depth = 0
  var inStr = false
  var esc = false
  var keys: seq[string] = @[]
  # Collect only depth-0 string keys: "name" followed by ':'.
  var pos = i
  var seen: seq[string] = @[]
  while pos < n:
    skipWs()
    # Re-sync i with pos for simplicity.
    i = pos
    if i >= n:
      break
    if payload[i] == '}' and depth == 0:
      break
    if payload[i] != '"':
      # Skip non-key content (numbers, nested structures) roughly.
      if payload[i] == '{' or payload[i] == '[':
        inc depth
      elif payload[i] == '}' or payload[i] == ']':
        if depth > 0:
          dec depth
      inc pos
      continue
    # Parse a string starting at i.
    var j = i + 1
    var buf = ""
    var e = false
    while j < n:
      let c = payload[j]
      if e:
        buf.add(c)
        e = false
      elif c == '\\':
        e = true
        buf.add(c)
      elif c == '"':
        break
      else:
        buf.add(c)
      inc j
    if j >= n:
      break
    # j points at closing quote. Look ahead for ':' skipping ws.
    var k = j + 1
    while k < n and payload[k] in {' ', '\t', '\n', '\r'}:
      inc k
    if k < n and payload[k] == ':' and depth == 0:
      if buf in seen:
        return true
      seen.add(buf)
      pos = k + 1
    else:
      pos = j + 1
    # Track nesting crudely from pos onward to stay at depth 0.
    # Recompute depth by scanning forward is overkill; instead update
    # depth when we pass braces outside strings. The loop above already
    # skips them, so keep a light update here.
    discard keys
  false

proc getRequiredString(claims: JsonNode, name: string,
    ok: var bool): string =
  if not claims.hasKey(name):
    ok = false
    return ""
  let v = claims[name]
  if v.kind != JString:
    ok = false
    return ""
  ok = true
  v.getStr()

proc getRequiredInt(claims: JsonNode, name: string,
    ok: var bool): int64 =
  if not claims.hasKey(name):
    ok = false
    return 0
  let v = claims[name]
  if v.kind != JInt:
    ok = false
    return 0
  ok = true
  v.getInt()

proc validateLicenseOffline*(
  token: string,
  trustedKeys: openArray[TrustedKey],
  expectedIss: string,
  expectedAud: string,
  now: int64,
  antidebug: AntiDebugPolicy = AntiDebugOff
): tuple[status: LicenseStatus, license: License] =
  ## Deterministic offline check. Never returns revoked.
  ## When antidebug.enabled, enforceNoDebugger() runs first and raises
  ## DebuggerDetected instead of returning.
  var res: tuple[status: LicenseStatus, license: License]
  res.status = malformed

  enforceNoDebugger(antidebug)

  if token.len == 0 or token.len > MaxTokenLen:
    res.status = malformed
    return res
  let parts = token.split('.')
  if parts.len != 3:
    res.status = malformed
    return res
  if parts[0].len == 0 or parts[1].len == 0 or parts[2].len == 0:
    res.status = malformed
    return res

  # --- Protected header: strict allowlist before crypto. ---
  var hdr: JsonNode
  try:
    hdr = parseJson(b64urlDecodeStr(parts[0]))
  except JoseError, JsonParsingError, ValueError:
    res.status = malformed
    return res
  if hdr.kind != JObject:
    res.status = malformed
    return res
  if not hdr.hasKey("alg") or hdr["alg"].kind != JString:
    res.status = malformed
    return res
  if hdr["alg"].getStr() != "EdDSA":
    res.status = wrongAlgorithm
    return res
  for k, _ in hdr:
    if k notin ["alg", "kid", "typ"]:
      res.status = malformed
      return res
  if hdr.hasKey("typ"):
    if hdr["typ"].kind != JString or hdr["typ"].getStr() != "JWT":
      res.status = malformed
      return res
  var kid = ""
  if hdr.hasKey("kid"):
    if hdr["kid"].kind != JString:
      res.status = malformed
      return res
    kid = hdr["kid"].getStr()
  let keyIdx = findTrustedKey(trustedKeys, kid)
  if keyIdx < 0:
    res.status = unknownKey
    return res

  # --- Signature first; trust nothing before this succeeds. ---
  let jwkKey = jwkOkpFromPub(trustedKeys[keyIdx].pubkey,
    trustedKeys[keyIdx].kid)
  var verified: JwsVerified
  try:
    verified = jwsVerify(token, jwkKey, [EdDSA])
  except JoseError as err:
    let msg = err.msg
    if "verification failed" in msg or "signature must be" in msg or
        "invalid base64url" in msg:
      res.status = badSignature
    elif "alg" in msg:
      res.status = wrongAlgorithm
    elif "kid" in msg or "no key found" in msg:
      res.status = unknownKey
    elif "crit" in msg or "compact serialization" in msg or
        "not valid JSON" in msg or "must be an object" in msg or
        "missing alg" in msg:
      res.status = malformed
    else:
      res.status = badSignature
    return res
  except ValueError:
    res.status = badSignature
    return res

  # --- Payload: strict JSON object, duplicate keys rejected. ---
  let payloadStr = payloadToStr(verified.payload)
  if payloadStr.len == 0 or payloadStr.len > MaxTokenLen:
    res.status = malformed
    return res
  if hasDuplicateTopLevelKeys(payloadStr):
    res.status = malformed
    return res
  var claims: JsonNode
  try:
    claims = parseJson(payloadStr)
  except JsonParsingError, ValueError:
    res.status = malformed
    return res
  if claims.kind != JObject:
    res.status = malformed
    return res

  # --- String claims. ---
  var ok = true
  let iss = getRequiredString(claims, "iss", ok)
  if not ok:
    res.status = malformed
    return res
  if iss != expectedIss:
    res.status = wrongIssuer
    return res
  if not claims.hasKey("aud"):
    res.status = wrongAudience
    return res
  var audOk = false
  let audNode = claims["aud"]
  if audNode.kind == JString:
    audOk = audNode.getStr() == expectedAud
  elif audNode.kind == JArray:
    for item in audNode:
      if item.kind == JString and item.getStr() == expectedAud:
        audOk = true
  if not audOk:
    res.status = wrongAudience
    return res
  let sub = getRequiredString(claims, "sub", ok)
  if not ok:
    res.status = malformed
    return res
  let jti = getRequiredString(claims, "jti", ok)
  if not ok:
    res.status = malformed
    return res
  let plan = getRequiredString(claims, "plan", ok)
  if not ok:
    res.status = malformed
    return res
  if plan.len == 0:
    res.status = malformed
    return res
  let customerId = getRequiredString(claims, "customer_id", ok)
  if not ok:
    res.status = malformed
    return res

  # --- Numeric claims: JInt only, no floats. ---
  let iat = getRequiredInt(claims, "iat", ok)
  if not ok:
    res.status = malformed
    return res
  let exp = getRequiredInt(claims, "exp", ok)
  if not ok:
    res.status = malformed
    return res
  if claims.hasKey("nbf"):
    if claims["nbf"].kind != JInt:
      res.status = malformed
      return res
    if claims["nbf"].getInt() > now + ClockLeeway:
      res.status = notYetValid
      return res

  # --- Lifetime policy: client caps what the signer may assert. ---
  if iat > now + MaxFutureIat:
    res.status = notYetValid
    return res
  if exp <= iat:
    res.status = malformed
    return res
  if exp - iat > MaxOfflineLifetime:
    res.status = lifetimeTooLong
    return res
  if now > exp + ClockLeeway:
    res.status = expired
    return res

  # --- Product claims. ---
  var features: seq[string] = @[]
  if claims.hasKey("features"):
    let f = claims["features"]
    if f.kind != JArray:
      res.status = malformed
      return res
    for item in f:
      if item.kind != JString:
        res.status = malformed
        return res
      features.add(item.getStr())
  var maxSeats = 0
  if claims.hasKey("max_seats"):
    if claims["max_seats"].kind != JInt:
      res.status = malformed
      return res
    maxSeats = int(claims["max_seats"].getInt())
    if maxSeats <= 0:
      res.status = malformed
      return res

  # --- Binding: schema reserved, only "none" accepted in Phase 1. ---
  var binding = Binding(kind: btNone)
  if claims.hasKey("binding"):
    let b = claims["binding"]
    if b.kind != JObject:
      res.status = malformed
      return res
    if not b.hasKey("type") or b["type"].kind != JString:
      res.status = malformed
      return res
    if b["type"].getStr() != "none":
      res.status = unsupportedBinding
      return res

  res.license = License(
    id: jti,
    subject: sub,
    plan: plan,
    features: features,
    maxSeats: maxSeats,
    customerId: customerId,
    issuedAt: iat,
    expiresAt: exp,
    binding: binding
  )
  res.status = valid
  res

proc validateLicenseOffline*(
  token: string,
  trustedKeys: openArray[TrustedKey],
  expectedIss: string,
  expectedAud: string,
  antidebug: AntiDebugPolicy = AntiDebugOff
): tuple[status: LicenseStatus, license: License] =
  ## Convenience overload using the system clock.
  validateLicenseOffline(token, trustedKeys, expectedIss, expectedAud,
    getTime().toUnix(), antidebug)
