# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from enum import StrEnum, unique


@unique
class JWKUsageType(StrEnum):
    """
    JWK Use
    """
    SIG = 'sig'
    ENC = 'enc'


__all__ = ['JWKUsageType']
