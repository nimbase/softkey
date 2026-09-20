# HACKER SERVER - adversarial fixture, never ship, localhost only.
#
# Simulates an attacker who controls the license endpoint. The client
# only honors signed replies over POST /v1/licenses/verify, so every
# mode here must fail closed into onlineUnavailable:
#
#   clue build tools/hacker_server.nim --out:hacker_server
#   ./hacker_server --port:18080 --mode:always-valid
#   ./hacker_server --port:18080 --mode:forged-signed
#   ./hacker_server --port:18080 --mode:chaos
#
# Modes:
#   always-valid  unsigned {"status":"valid"} for every jti (verdict
#                 forgery; client rejects: no signature)
#   forged-signed status-shaped reply signed with a fresh random key
#                 under kid "hacker-status-key" (client rejects:
#                 unknown key / bad signature)
#   chaos         hostile replies by jti:
#                   chaos-garbage -> 200 with a non-JSON body
#                   chaos-big     -> 200 with a 20KB body (over client cap)
#                   chaos-drip    -> 10s stall, then valid (beats short timeouts)
#                   anything else -> unsigned valid (as always-valid)
#
# Synchronous std/net server, 127.0.0.1 only. The drip case blocks the
# single accept loop while stalling; run it last.

import std/json
import std/net
import std/os
import std/parseopt
import std/strutils
import std/sysrand
import std/times

import jose

const MaxBody = 16384

proc isSafeJti(s: string): bool =
  if s.len == 0 or s.len > 256:
    return false
  for c in s:
    if c notin {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-', '_', '.'}:
      return false
  true

proc sendRaw(client: Socket, code: string, contentType, body: string) =
  client.send("HTTP/1.1 " & code & "\r\n" &
    "Content-Type: " & contentType & "\r\n" &
    "Content-Length: " & $body.len & "\r\n" &
    "Connection: close\r\n\r\n" & body)

proc sendJson(client: Socket, code: string, node: JsonNode) =
  sendRaw(client, code, "application/json", $node)

proc sendCompact(client: Socket, token: string) =
  sendRaw(client, "200 OK", "application/jose", token)

proc hackerKey(): Jwk =
  ## Fresh random key per request batch: the attacker never holds the
  ## real signing key, so every forged signature must fail verification.
  let raw = urandom(32)
  var seed: array[32, byte]
  for i in 0 ..< 32:
    seed[i] = raw[i]
  jwkOkpFromSeed(seed, "hacker-status-key")

proc handleClient(client: Socket, mode: string) =
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
      return
    if not (meth == "POST" and path == "/v1/licenses/verify"):
      sendJson(client, "404 Not Found", %*{"error": "not found"})
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
    var lh = ""
    var nonce = ""
    if node.hasKey("license_hash") and
        node["license_hash"].kind == JString:
      lh = node["license_hash"].getStr()
    if node.hasKey("nonce") and node["nonce"].kind == JString:
      nonce = node["nonce"].getStr()
    if mode == "chaos":
      case jti
      of "chaos-garbage":
        sendRaw(client, "200 OK", "application/json", "this is not json{{{")
        return
      of "chaos-big":
        sendRaw(client, "200 OK", "application/json",
          "{\"status\":\"" & repeat('V', 20 * 1024) & "\"}")
        return
      of "chaos-drip":
        sleep(10_000)
        sendJson(client, "200 OK", %*{"jti": jti, "status": "valid"})
        return
      else:
        sendJson(client, "200 OK", %*{"jti": jti, "status": "valid"})
        return
    if mode == "forged-signed":
      # Correct shape, wrong key: must fail signature verification.
      let now = getTime().toUnix()
      let payload = %*{
        "iss": "your-company",
        "aud": "your-product",
        "license_hash": lh,
        "nonce": nonce,
        "status": "valid",
        "features": ["export", "admin"],
        "iat": now,
        "exp": now + 300
      }
      sendCompact(client, jwsSign(EdDSA, hackerKey(), $payload))
      return
    # always-valid: unsigned forgery, correctly shaped JSON but no JWS.
    sendJson(client, "200 OK", %*{"jti": jti, "status": "valid"})
  except CatchableError:
    discard
  finally:
    try: client.close()
    except CatchableError: discard

proc main() =
  var port = 18080
  var mode = "always-valid"
  for kind, key, val in getopt():
    case key
    of "port": port = parseInt(val)
    of "mode": mode = val
    else: discard
  if mode notin ["always-valid", "forged-signed", "chaos"]:
    quit("unknown --mode (always-valid|forged-signed|chaos)", 1)
  echo "HACKER SERVER (adversarial fixture, never ship) on 127.0.0.1:" &
    $port & " mode=" & mode
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
    handleClient(client, mode)

when isMainModule:
  main()
