# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from .rsa_jwk import RSAJWK
from .ec_jwk import ECJWK
from .okp_jwk import OKPJWK
from .octet_jwk import OctetJWK

JWK = RSAJWK | ECJWK | OKPJWK | OctetJWK

__all__ = [
    'JWK'
]
