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

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}.{self.name}'

    def __str__(self) -> str:
        return self.value


__all__ = ['JWKUsageType']
