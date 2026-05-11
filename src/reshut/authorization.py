# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import inspect
from typing import Any, Callable, Optional, TypeAlias, cast


ClaimEvaluator: TypeAlias = Callable[[Any], bool]


def allow_anonymous(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Indicates that a handler does not require Authorization.

    :param func: The handler function.
    :return: The handler function (not wrapped.)
    """
    org = inspect.unwrap(func)
    setattr(org, '__reshut_noauth', True)
    return func


def allow_claim(
    func: Callable[..., Any],
    claim_name: str,
    claim_check: Optional[Any | ClaimEvaluator] = None,
    is_required: bool = False
) -> Callable[..., Any]:
    """
    Adds an ALLOW claim rule to a handler.
    
    When at least one ALLOW claim rule is defined on a handler, then access is denied if at least one of the allowed claims is not presented.

    :param func: The handler function.
    :param claim_name: Claim name.
    :param claim_check: Optional literal value that the claim must present, or a ``ClaimEvaluator`` that checks the claim is a match.
    :param is_required: Optional boolean indicating that the claim is required, forming a "REQUIRED claim rule".
    :return: The handler function (not wrapped.)
    """
    bag_name = '__reshut_require' if is_required else '__reshut_allow'
    org = inspect.unwrap(func)
    if not hasattr(org, bag_name):
        setattr(org, bag_name, dict[str, Any]({
            claim_name: claim_check
        }))
    else:
        allow_list = cast(dict[str, Any],getattr(org, bag_name))
        allow_list[claim_name] = claim_check
    return func


def deny_claim(
    func: Callable[..., Any],
    claim_name: str,
    claim_check: Optional[Any | ClaimEvaluator] = None
) -> Callable[..., Any]:
    """
    Adds a DENY claim rule to a handler.

    When any presented claim matches a DENY claim rule, then access is denied.

    :param func: The handler function.
    :param claim_name: Claim name.
    :param claim_check: Optional literal value that the claim must NOT present, or a ``ClaimEvaluator`` that checks the claim is a match.
    :return: The handler function (not wrapped.)
    """
    org = inspect.unwrap(func)
    if not hasattr(org, '__reshut_deny'):
        setattr(org, '__reshut_deny', {
            claim_name: claim_check
        })
    else:
        deny_list = cast(dict[str, Any], getattr(org, '__reshut_deny'))
        deny_list[claim_name] = claim_check
    return func


def require_claim(
    func: Callable[..., Any],
    claim_name: str,
    claim_check: Optional[Any | ClaimEvaluator] = None
) -> Callable[..., Any]:
    """
    Adds a REQUIRED claim rule to a handler.

    When all required claims are presented, then access is granted.
    
    :param func: The handler function.
    :param claim_name: Claim name.
    :param claim_check: Optional literal value that the claim must present, or a ``ClaimEvaluator`` that checks the claim is a match.
    :return: The handler function (not wrapped.)
    """
    return allow_claim(func, claim_name, claim_check, True)


__all__ = [
    'ClaimEvaluator',
    'allow_anonymous',
    'allow_claim',
    'deny_claim',
    'require_claim'
]
