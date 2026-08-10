# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import Literal

from ._jwk import _JWK
from .jwk_key_type import JWKKeyType


class RSAJWK(_JWK, total=False):
    kty: Literal[JWKKeyType.RSA]
    n: str
    e: str
    # prikey fields
    d: str
    p: str
    q: str
    dp: str
    dq: str
    qi: str


__all__ = ['RSAJWK']
