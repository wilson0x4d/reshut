# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import TypedDict

from ..algorithm import Algorithm
from .jwk_usage_type import JWKUsageType


class _JWK(TypedDict, total=False):
    kid: str
    use: JWKUsageType
    alg: Algorithm


__all__ = ['_JWK']
