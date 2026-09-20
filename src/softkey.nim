# softkey: offline license validation (JWS EdDSA) + optional online layer.
#
# Server holds the Ed25519 private key. This package embeds only
# public verification keys and enforces a strict offline profile.
# Online checks are advisory revocation signals keyed by jti.

import ./softkey/license_types
import ./softkey/license_verify
import ./softkey/antidebug
import ./softkey/license_online

export license_types
export license_verify
export antidebug
export license_online
