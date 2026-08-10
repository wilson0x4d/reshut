# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from enum import StrEnum, unique


@unique
class JWKCurveType(StrEnum):
    P256 = 'P-256'
    P384 = 'P-384'
    P521 = 'P-521'
    ED25519 = 'Ed25519'
    ED448 = 'Ed448'


__all__ = ['JWKCurveType']
