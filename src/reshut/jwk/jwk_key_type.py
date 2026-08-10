# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from enum import StrEnum, unique


@unique
class JWKKeyType(StrEnum):
    """
    JWK Key Type
    """
    RSA = 'RSA'
    EC = 'EC'
    OKP = 'OKP'
    OCT = 'oct'


__all__ = ['JWKKeyType']
