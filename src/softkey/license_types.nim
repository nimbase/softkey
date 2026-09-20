# Offline license types: JWS EdDSA (Ed25519) verification only.
#
# The application embeds Ed25519 *public* keys. The private signing key
# lives on the license server / HSM and is never distributed.

type
  LicenseStatus* = enum
    valid
    malformed
    badSignature
    wrongAlgorithm
    unknownKey
    wrongIssuer
    wrongAudience
    expired
    notYetValid
    lifetimeTooLong
    unsupportedBinding
    revoked ## Only via combined online path; never from offline alone.

  BindingType* = enum
    btNone
    btEd25519

  Binding* = object
    case kind*: BindingType
    of btNone:
      discard
    of btEd25519:
      keyId*: string
      pubkeyHash*: array[32, byte]

  License* = object
    id*: string ## jti claim
    subject*: string ## sub claim
    plan*: string
    features*: seq[string]
    maxSeats*: int
    customerId*: string
    issuedAt*: int64
    expiresAt*: int64
    binding*: Binding

  TrustedKey* = object
    ## One allowlisted product verification key.
    kid*: string
    pubkey*: array[32, byte]

  OnlineStatus* = enum
    onlineNotChecked ## No online check ran (offline failed or no checker).
    onlineValid
    onlineRevoked
    renewalRequired
    onlineUnavailable ## Transport error, timeout, or bad server reply.

  OnlinePolicy* = object
    baseUrl*: string ## e.g. http://127.0.0.1:8080, no trailing slash.
    timeoutMs*: int ## HTTP timeout, default 2000.
    allowUnavailable*: bool ## Fail-open when server unreachable.
    requireOnline*: bool ## If true, unavailable denies even valid offline.
    statusMaxAgeSec*: int64 ## Max reply exp-iat. Default 300 (NOT key
      ## validity: keys rotate via kid allowlist, replies expire via this).
    statusLeewaySec*: int64 ## Clock skew for reply iat/exp. Default 60.

  StatusQuery* = object
    ## One online status request. The nonce is fresh per call; the hash
    ## binds the reply to the exact license token presented; features
    ## are the offline license features the reply may only narrow.
    jti*: string
    licenseHash*: string ## Lowercase hex SHA-256 of the compact license.
    nonce*: string ## base64url-no-pad of 32 random bytes.
    features*: seq[string]

  CombinedResult* = object
    offline*: LicenseStatus
    online*: OnlineStatus
    license*: License

  SecurityStatus* = enum
    securityOk ## No debugger indicators found.
    debuggerDetected ## At least one tracer indicator was positive.
    unsupportedEnvironment ## Platform or check unavailable; nothing asserted.

  AntiDebugPolicy* = object
    enabled*: bool ## Default false: no behavior change unless opted in.
    allowUnsupported*: bool ## If true, unsupported env proceeds silently.

const
  AntiDebugOff* = AntiDebugPolicy(enabled: false, allowUnsupported: true)
    ## Default policy: anti-debug checks disabled.

proc defaultOnlinePolicy*(baseUrl: string): OnlinePolicy =
  OnlinePolicy(baseUrl: baseUrl, timeoutMs: 2000,
    allowUnavailable: true, requireOnline: false,
    statusMaxAgeSec: 300, statusLeewaySec: 60)

proc defaultAntiDebugPolicy*(): AntiDebugPolicy =
  AntiDebugPolicy(enabled: true, allowUnsupported: true)

const
  MaxOfflineLifetime* = 90'i64 * 24 * 3600 ## 90 days in seconds.
  ClockLeeway* = 60'i64
  MaxFutureIat* = 60'i64
  MaxTokenLen* = 8192
