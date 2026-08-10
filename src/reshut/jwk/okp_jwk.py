# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import Literal

from ._jwk import _JWK
from .jwk_curve_type import JWKCurveType
from .jwk_key_type import JWKKeyType


class OKPJWK(_JWK, total=False):
    kty: Literal[JWKKeyType.OKP]
    crv: Literal[JWKCurveType.ED25519, JWKCurveType.ED448]
    x: str
    # prikey fields
    d: str


__all__ = ['OKPJWK']
