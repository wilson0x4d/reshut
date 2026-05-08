# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from enum import StrEnum, unique


@unique
class Algorithm(StrEnum):
    """
    Enumeration of Algorithms that can be used for tokenizing claims.
    """
    HS256 = 'HS256'
    """HMAC (256-bit, symmetric, fastest)"""
    HS384 = 'HS384'
    """HMAC (384-bit, symmetric, fastest)"""
    HS512 = 'HS512'
    """HMAC (512-bit, symmetric, fastest)"""
    RS256 = 'RS256'
    """RSA (256-bit, asymmetric, slow)"""
    RS384 = 'RS384'
    """RSA (384-bit, asymmetric, slow)"""
    RS512 = 'RS512'
    """RSA (512-bit, asymmetric, slow)"""
    ES256 = 'ES256'
    """Elliptic-curve (256-bit, asymmetric, fast)"""
    ES384 = 'ES384'
    """Elliptic-curve (384-bit, asymmetric, fast)"""
    ES512 = 'ES512'
    """Elliptic-curve (512-bit, asymmetric, fast)"""
    ED25519 = 'ED25519'
    """Edwards-curve (256-bit, asymmetric, faster)"""
    ED448 = 'ED448'
    """Edwards-curve (448-bit, asymmetric, faster)"""
    def __str__(self) -> str:
        return self.value    


__all__ = [
    'Algorithm'
]