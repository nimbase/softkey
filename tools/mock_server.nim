# Mock license server (development / tests only, localhost only).
#
# Holds the DEV status signing key below. That key is test-only and
# must never ship: production signs with the real license key kept in
# an HSM / vault. This mock exists so the signed-reply contract can be
# exercised without secret infrastructure.
#
#   clue build tools/mock_server.nim --out:mock_server
#   ./mock_server --port:8080 --seed:tools/revocations.json
#
# Routes (POST-only; no unsigned legacy GET status route):
#   GET  /health                 -> {"ok": true}
#   POST /v1/licenses/verify     -> {"jti","license_hash","nonce"} in,
#                                   compact JWS status reply out
#   POST /v1/admin/revoke        -> {"jti":...} adds to memory set
#   POST /v1/admin/reset         -> reload seed file
#
# Reply payload: iss, aud, license_hash (echoed), nonce (echoed),
# status, features, iat, exp (iat+300, inside the 300s client cap).
# Bodies over 16KB are rejected with 413.

import std/json
import std/net
import std/parseopt
import std/strutils
import std/tables
import std/times

import jose

const
  MaxBody = 16384
  MockIss = "your-company"
  MockAud = "your-product"
  MockKid = "license-signing-key-2026-01"

# DEV-ONLY signing key (test seed bytes 1..32, same as the test suite).
# NEVER SHIP. Production uses the real license key from secure storage.
proc devStatusKey(): Jwk =
  var seed: array[32, byte]
  for i in 0 ..< 32:
    seed[i] = byte(i + 1)
  jwkOkpFromSeed(seed, MockKid)

var revoked = initTable[string, bool]()
var renewal = initTable[string, bool]()
var seedPath = "tools/revocations.json"

proc isSafeJti(s: string): bool =
  if s.len == 0 or s.len > 256:
    return false
  for c in s:
    if c notin {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-', '_', '.'}:
      return false
  true

proc isHexStr(s: string): bool =
  if s.len == 0 or s.len > 256:
    return false
  for c in s:
    if c notin {'0' .. '9', 'a' .. 'f', 'A' .. 'F'}:
      return false
  true

proc isB64Str(s: string): bool =
  if s.len == 0 or s.len > 256:
    return false
  for c in s:
    if c notin {'A' .. 'Z', 'a' .. 'z', '0' .. '9', '-', '_'}:
      return false
  true

proc loadSeed() =
  revoked.clear()
  renewal.clear()
  var node: JsonNode
  try:
    node = parseJson(readFile(seedPath))
  except CatchableError:
    return
  if node.kind != JObject:
    return
  if node.hasKey("revoked") and node["revoked"].kind == JArray:
    for item in node["revoked"]:
      if item.kind == JString and isSafeJti(item.getStr()):
        revoked[item.getStr()] = true
  if node.hasKey("renewal") and node["renewal"].kind == JArray:
    for item in node["renewal"]:
      if item.kind == JString and isSafeJti(item.getStr()):
        renewal[item.getStr()] = true

proc statusFor(jti: string): string =
  if revoked.hasKey(jti): "revoked"
  elif renewal.hasKey(jti): "renewal_required"
  else: "valid"

proc sendJson(client: Socket, code: string, node: JsonNode) =
  let body = $node
  client.send("HTTP/1.1 " & code & "\r\n" &
    "Content-Type: application/json\r\n" &
    "Content-Length: " & $body.len & "\r\n" &
    "Connection: close\r\n\r\n" & body)

proc sendCompact(client: Socket, token: string) =
  client.send("HTTP/1.1 200 OK\r\n" &
    "Content-Type: application/jose\r\n" &
    "Content-Length: " & $token.len & "\r\n" &
    "Connection: close\r\n\r\n" & token)

proc handleClient(client: Socket, statusKey: Jwk) =
  try:
    let reqLine = client.recvLine().strip()
    if reqLine.len == 0:
      return
    let parts = reqLine.split(' ')
    if parts.len < 2:
      return
    let meth = parts[0]
    let path = parts[1]
    var contentLen = 0
    while true:
      let line = client.recvLine().strip()
      if line.len == 0:
        break
      if line.toLowerAscii().startsWith("content-length:"):
        try:
          contentLen = parseInt(line.split(':')[1].strip())
        except ValueError:
          discard
    var body = ""
    if contentLen > 0:
      if contentLen > MaxBody:
        sendJson(client, "413 Payload Too Large",
          %*{"error": "body too large"})
        return
      var remaining = contentLen
      while remaining > 0:
        let chunk = client.recv(min(remaining, 4096))
        if chunk.len == 0:
          break
        body.add(chunk)
        remaining -= chunk.len
    if meth == "GET" and path == "/health":
      sendJson(client, "200 OK", %*{"ok": true})
    elif meth == "POST" and
        (path == "/v1/licenses/verify" or path == "/v1/admin/revoke" or
        path == "/v1/admin/reset"):
      if path == "/v1/admin/reset":
        loadSeed()
        sendJson(client, "200 OK", %*{"ok": true})
        return
      var node: JsonNode
      try:
        node = parseJson(if body.len == 0: "{}" else: body)
      except JsonParsingError, ValueError:
        sendJson(client, "400 Bad Request", %*{"error": "invalid json"})
        return
      if node.kind != JObject or not node.hasKey("jti") or
          node["jti"].kind != JString:
        sendJson(client, "400 Bad Request", %*{"error": "missing jti"})
        return
      let jti = node["jti"].getStr()
      if not isSafeJti(jti):
        sendJson(client, "400 Bad Request", %*{"error": "bad jti"})
        return
      if path == "/v1/admin/revoke":
        revoked[jti] = true
        sendJson(client, "200 OK", %*{"jti": jti, "status": "revoked"})
        return
      if not node.hasKey("license_hash") or
          node["license_hash"].kind != JString or
          not isHexStr(node["license_hash"].getStr()) or
          not node.hasKey("nonce") or node["nonce"].kind != JString or
          not isB64Str(node["nonce"].getStr()):
        sendJson(client, "400 Bad Request",
          %*{"error": "missing license_hash/nonce"})
        return
      let now = getTime().toUnix()
      let payload = %*{
        "iss": MockIss,
        "aud": MockAud,
        "license_hash": node["license_hash"].getStr(),
        "nonce": node["nonce"].getStr(),
        "status": statusFor(jti),
        "features": ["export"],
        "iat": now,
        "exp": now + 300
      }
      sendCompact(client, jwsSign(EdDSA, statusKey, $payload))
    else:
      sendJson(client, "404 Not Found", %*{"error": "not found"})
  except CatchableError:
    discard
  finally:
    try: client.close()
    except CatchableError: discard

proc main() =
  var port = 8080
  for kind, key, val in getopt():
    case key
    of "port": port = parseInt(val)
    of "seed": seedPath = val
    else: discard
  loadSeed()
  let statusKey = devStatusKey()
  echo "mock license server on 127.0.0.1:" & $port & " seed=" & seedPath
  var server = newSocket()
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(Port(port), "127.0.0.1")
  server.listen()
  while true:
    var client = newSocket()
    try:
      server.accept(client)
    except CatchableError:
      try: client.close()
      except CatchableError: discard
      continue
    handleClient(client, statusKey)

when isMainModule:
  main()
