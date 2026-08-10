# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import Literal

from ._jwk import _JWK
from .jwk_key_type import JWKKeyType


class OctetJWK(_JWK, total=False):
    kty: Literal[JWKKeyType.OCT]
    k: str


__all__ = ['OctetJWK']
