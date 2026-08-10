# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Any, Mapping, Optional, cast

import falcon
from punit import theory, inlinedata
from reshut.middleware import AuthorizationEvaluator
from reshut.middleware import ASGIAuthorizationMiddleware
from reshut.middleware import TokenEvaluator


class _DummyRequest:
    __headers: Mapping[str, str]

    def __init__(self, headers: Optional[Mapping[str, str]] = None) -> None:
        self.__headers = headers or {}

    def get_header(self, name: str, required: bool = False, default: Any = None) -> Any:  # noqa: D401
        return self.__headers.get(name, default)


class _DummyHandler:
    __reshut_allow: Optional[list[tuple[str, Any]]] = None
    __reshut_deny: Optional[list[tuple[str, Any]]] = None
    __reshut_require: Optional[list[tuple[str, Any]]] = None


# type: ignore[override]
class _StubTokenEvaluator(TokenEvaluator):
    __result: bool
    __calls: list[tuple[str, list[tuple[str, Any]], list[tuple[str, Any]], list[tuple[str, Any]]]]

    def __init__(self, result: bool) -> None:
        self.__result = result
        self.__calls = []

    def evaluate(
        self,
        token: str,
        deny_claims: list[tuple[str, Any]],
        allow_claims: list[tuple[str, Any]],
        require_claims: list[tuple[str, Any]],
    ) -> bool:
        self.__calls.append((token, deny_claims, allow_claims, require_claims))
        return self.__result

    @property
    def calls(self) -> list[tuple[str, list[tuple[str, Any]], list[tuple[str, Any]], list[tuple[str, Any]]]]:
        return self.__calls


@theory
@inlinedata(True, False, False, "only 'apikey'")
@inlinedata(False, True, False, "only 'basic'")
@inlinedata(False, False, True, "only 'bearer")
@inlinedata(True, True, True, "expected apikey+basic+bearer")
@inlinedata(True, False, True, "expected apikey+bearer")
@inlinedata(False, True, True, "expected basic+bearer")
@inlinedata(True, True, False, "expected apikey+basic")
def can_interrogate_authorization_methods(with_apikey: bool, with_basic: bool, with_bearer: bool, reason: str) -> None:
    apikey_token_evaluator = None if not with_apikey else _StubTokenEvaluator(result=True)
    basic_token_evaluator = None if not with_basic else _StubTokenEvaluator(result=True)
    bearer_token_evaluator = None if not with_bearer else _StubTokenEvaluator(result=True)
    auth_middleware = ASGIAuthorizationMiddleware(  # type: ignore[arg-type]
        apikey_token_evaluator,
        basic_token_evaluator,
        bearer_token_evaluator)
    assert auth_middleware.supports_apikey == with_apikey, reason
    assert auth_middleware.supports_basic == with_basic, reason
    assert auth_middleware.supports_bearer == with_bearer, reason
