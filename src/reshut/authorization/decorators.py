# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import inspect
from typing import Any, Callable, Optional, cast


from .claim_evaluator import ClaimEvaluator


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

    Multiple decorators with the same ``claim_name`` are cumulative — each ``@allow_claim`` appends a separate rule.
    At evaluation, any matching claim grants access (OR semantics).

    Example — stack same claim name with different checks:

    .. code-block:: python

        @allow_claim("scope", "read")
        @allow_claim("scope", "write")
        def on_get(self, req, resp):
            # "read" OR "write" will pass

    :param func: The handler function.
    :param claim_name: Claim name.
    :param claim_check: Optional literal value that the claim must present, or a ``ClaimEvaluator`` that checks the claim is a match.
    :param is_required: Optional boolean indicating that the claim is required, forming a "REQUIRED claim rule".
    :return: The handler function (not wrapped.)
    """
    bag_name = '__reshut_require' if is_required else '__reshut_allow'
    org = inspect.unwrap(func)
    if not hasattr(org, bag_name):
        setattr(org, bag_name, list[tuple[str, Any]]())
    claim_rules = cast(list[tuple[str, Any]], getattr(org, bag_name))
    claim_rules.append((claim_name, claim_check))
    return func


def deny_claim(
    func: Callable[..., Any],
    claim_name: str,
    claim_check: Optional[Any | ClaimEvaluator] = None
) -> Callable[..., Any]:
    """
    Adds a DENY claim rule to a handler.

    When any presented claim matches a DENY claim rule, then access is denied.

    Multiple decorators with the same ``claim_name`` are cumulative — each ``@deny_claim`` appends a separate rule.
    At evaluation, any matching claim blocks access (OR within the deny set).

    Example — stack same claim name with different checks:

    .. code-block:: python

        @deny_claim("scope", "admin-only")
        @deny_claim("scope", "readonly")
        def on_patch(self, req, resp):
            # blocks if scope is "admin-only" OR "readonly"

    :param func: The handler function.
    :param claim_name: Claim name.
    :param claim_check: Optional literal value that the claim must NOT present, or a ``ClaimEvaluator`` that checks the claim is a match.
    :return: The handler function (not wrapped.)
    """
    org = inspect.unwrap(func)
    if not hasattr(org, '__reshut_deny'):
        setattr(org, '__reshut_deny', list[tuple[str, Any]]())
    claim_rules = cast(list[tuple[str, Any]], getattr(org, '__reshut_deny'))
    claim_rules.append((claim_name, claim_check))
    return func


def require_claim(
    func: Callable[..., Any],
    claim_name: str,
    claim_check: Optional[Any | ClaimEvaluator] = None
) -> Callable[..., Any]:
    """
    Adds a REQUIRED claim rule to a handler.

    When all required claims are presented, then access is granted.

    Multiple decorators with the same ``claim_name`` are cumulative — each ``@require_claim`` appends a separate rule.
    At evaluation, all listed claims must match (AND semantics).

    Example — stack decorators with same claim name:

    .. code-block:: python

        @require_claim("role", "admin")
        @require_claim("scope", "write")
        def on_delete(self, req, resp):
            # both role=admin AND scope=write required

    :param func: The handler function.
    :param claim_name: Claim name.
    :param claim_check: Optional literal value that the claim must present, or a ``ClaimEvaluator`` that checks the claim is a match.
    :return: The handler function (not wrapped.)
    """
    return allow_claim(func, claim_name, claim_check, True)


__all__ = [
    'allow_anonymous',
    'allow_claim',
    'deny_claim',
    'require_claim'
]
