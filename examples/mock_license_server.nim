# Mock license server for the examples/ showcase.
#
# LOCAL TEST FIXTURE ONLY. Binds 127.0.0.1. Holds the DEMO
# online-response private seed, which is NOT production-safe.
#
# Speaks the same endpoint contract as the softkey library checker:
#   POST /v1/licenses/verify  {"jti","license_hash","nonce"} in,
#                             compact JWS status reply out
# (The task brief suggests POST /verify; this fixture reuses the
# library path instead so premium_cli needs no custom transport code.)
#
# Usage:
#   clue build examples/mock_license_server.nim --out:mock_license_server
#   ./mock_license_server --port:18081
#   ./mock_license_server --port:18081 --status:revoked
#   ./mock_license_server --port:18081 --mode:unsigned      # attacker: bare JSON
#   ./mock_license_server --port:18081 --mode:random-key    # attacker: wrong key
#   ./mock_license_server --port:18081 --mode:wrong-nonce
#   ./mock_license_server --port:18081 --mode:wrong-license
#   ./mock_license_server --port:18081 --mode:expired
#   ./mock_license_server --port:18081 --mode:malformed
#
# Every --mode value simulates an attacker or failure the CLI must
# reject (mapping to onlineUnavailable, never a positive verdict).

import std/json
import std/net
import std/parseopt
import std/strutils
import std/sysrand
import std/times

import jose

import ./dev_keys

const MaxBody = 16384

proc devOnlineKey(): Jwk =
  jwkOkpFromSeed(demoOnlineSeed(), DemoOnlineKid)

proc attackerKey(): Jwk =
  let raw = urandom(32)
  var seed: array[32, byte]
  for i in 0 ..< 32:
    seed[i] = raw[i]
  jwkOkpFromSeed(seed, "attacker-online-key")

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
    if c notin {'A' .. 'Z', 'a' .. 'z', '0' .. '9', '-', '_', '='}:
      return false
  true

proc sendRaw(client: Socket, code, contentType, body: string) =
  client.send("HTTP/1.1 " & code & "\r\n" &
    "Content-Type: " & contentType & "\r\n" &
    "Content-Length: " & $body.len & "\r\n" &
    "Connection: close\r\n\r\n" & body)

proc reply(statusKey: Jwk, licenseHash, nonce, status: string,
    mutate: string): string =
  ## Build the signed reply, applying one attacker mutation.
  let now = getTime().toUnix()
  var lh = licenseHash
  var nn = nonce
  var exp = now + 300
  if mutate == "wrong-nonce":
    nn = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  if mutate == "wrong-license":
    lh = "0000000000000000000000000000000000000000000000000000000000000000"
  if mutate == "expired":
    exp = now - 3600
  let payload = %*{
    "iss": DemoIss,
    "aud": DemoOnlineAud,
    "license_hash": lh,
    "nonce": nn,
    "status": status,
    "features": ["run"],
    "iat": now,
    "exp": exp
  }
  let key = if mutate == "random-key": attackerKey() else: statusKey
  jwsSign(EdDSA, key, $payload)

proc handleClient(client: Socket, statusKey: Jwk, status, mode: string) =
  try:
    let reqLine = client.recvLine().strip()
    if reqLine.len == 0:
      return
    let parts = reqLine.split(' ')
    if parts.len < 2:
      return
    if parts[0] != "POST" or parts[1] != "/v1/licenses/verify":
      sendRaw(client, "404 Not Found", "application/json",
        """{"error":"not found"}""")
      return
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
        sendRaw(client, "413 Payload Too Large", "application/json",
          """{"error":"body too large"}""")
        return
      var remaining = contentLen
      while remaining > 0:
        let chunk = client.recv(min(remaining, 4096))
        if chunk.len == 0:
          break
        body.add(chunk)
        remaining -= chunk.len
    var node: JsonNode
    try:
      node = parseJson(if body.len == 0: "{}" else: body)
    except JsonParsingError, ValueError:
      sendRaw(client, "400 Bad Request", "application/json",
        """{"error":"invalid json"}""")
      return
    if node.kind != JObject or not node.hasKey("license_hash") or
        node["license_hash"].kind != JString or
        not isHexStr(node["license_hash"].getStr()) or
        not node.hasKey("nonce") or node["nonce"].kind != JString or
        not isB64Str(node["nonce"].getStr()):
      sendRaw(client, "400 Bad Request", "application/json",
        """{"error":"missing license_hash/nonce"}""")
      return
    let lh = node["license_hash"].getStr()
    let nn = node["nonce"].getStr()
    case mode
    of "unsigned":
      sendRaw(client, "200 OK", "application/json",
        """{"status":"valid"}""")
    of "malformed":
      sendRaw(client, "200 OK", "application/jose", "not.a.token")
    else:
      sendRaw(client, "200 OK", "application/jose",
        reply(statusKey, lh, nn, status, mode))
  except CatchableError:
    discard
  finally:
    try: client.close()
    except CatchableError: discard

proc main() =
  var port = 18081
  var status = "valid"
  var mode = "honest"
  for kind, key, val in getopt():
    case key
    of "port": port = parseInt(val)
    of "status": status = val
    of "mode": mode = val
    else: discard
  if status notin ["valid", "revoked"]:
    stderr.writeLine("mock_license_server: --status must be valid|revoked")
    quit(2)
  if mode notin ["honest", "unsigned", "wrong-nonce", "wrong-license",
      "random-key", "expired", "malformed"]:
    stderr.writeLine("mock_license_server: unknown --mode: " & mode)
    quit(2)
  echo "mock license server (TEST FIXTURE, demo keys) on 127.0.0.1:" &
    $port & " status=" & status & " mode=" & mode
  let statusKey = devOnlineKey()
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
    handleClient(client, statusKey, status, mode)

when isMainModule:
  main()
