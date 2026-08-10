# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import Any, Callable, TypeAlias


ClaimEvaluator: TypeAlias = Callable[[Any], bool]

__all__ = ['ClaimEvaluator']
