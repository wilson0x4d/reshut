# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, cast

import falcon
from punit import fact, exceptions
from reshut.middleware.AuthorizationEvaluator import AuthorizationEvaluator
from reshut.middleware.TokenEvaluator import TokenEvaluator


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


class _StubTokenEvaluator(TokenEvaluator):
    __result: bool
    __calls: list[tuple[str, list[tuple[str, Any]], list[tuple[str, Any]], list[tuple[str, Any]]]]

    def __init__(self, result: bool) -> None:
        self.__result = result
        self.__calls = []

    def evaluate(
        self,
        token: str,
        deny: list[tuple[str, Any]],
        allow: list[tuple[str, Any]],
        require: list[tuple[str, Any]],
    ) -> bool:
        self.__calls.append((token, deny, allow, require))
        return self.__result

    @property
    def calls(self) -> list[tuple[str, list[tuple[str, Any]], list[tuple[str, Any]], list[tuple[str, Any]]]]:
        return self.__calls


@fact
def evaluate_apikey_successful() -> None:
    token_evaluator = _StubTokenEvaluator(result=True)

    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=token_evaluator,
        basic_token_evaluator=None,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={'X-API-Key': 'valid-apikey'}))
    handler = _DummyHandler()

    auth_evaluator.evaluate(request, handler)  # should not raise

    assert len(token_evaluator.calls) == 1
    token, deny, allow, require = token_evaluator.calls[0]
    assert token == 'valid-apikey'
    assert deny == []
    assert allow == []
    assert require == []


@fact
def evaluate_basic_successful() -> None:
    token_evaluator = _StubTokenEvaluator(result=True)

    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=None,
        basic_token_evaluator=token_evaluator,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={'Authorization': 'Basic dXNlcjpwYXNz'}))
    handler = _DummyHandler()

    auth_evaluator.evaluate(request, handler)

    assert len(token_evaluator.calls) == 1
    token, _, _, _ = token_evaluator.calls[0]
    assert token == 'dXNlcjpwYXNz'


@fact
def evaluate_bearer_successful() -> None:
    token_evaluator = _StubTokenEvaluator(result=True)

    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=None,
        basic_token_evaluator=None,
        bearer_token_evaluator=token_evaluator,
    )
    request = cast(falcon.Request, _DummyRequest(headers={'Authorization': 'Bearer abc123xyz'}))
    handler = _DummyHandler()

    auth_evaluator.evaluate(request, handler)

    assert len(token_evaluator.calls) == 1
    token, _, _, _ = token_evaluator.calls[0]
    assert token == 'abc123xyz'


@fact
def when_missing_auth_then_httpbadrequest() -> None:
    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=None,
        basic_token_evaluator=None,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={}))
    handler = _DummyHandler()

    assert exceptions.raises[falcon.HTTPBadRequest](
        lambda: auth_evaluator.evaluate(request, handler)
    )


@fact
def when_unsupported_scheme_then_httpbadrequest() -> None:
    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=None,
        basic_token_evaluator=None,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={'Authorization': 'Digest some-token'}))
    handler = _DummyHandler()

    assert exceptions.raises[falcon.HTTPBadRequest](
        lambda: auth_evaluator.evaluate(request, handler)
    )


@fact
def evaluate_evaluator_returns_false_raises_httpunauthorized() -> None:
    token_evaluator = _StubTokenEvaluator(result=False)

    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=token_evaluator,
        basic_token_evaluator=None,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={'X-API-Key': 'bad-key'}))
    handler = _DummyHandler()

    assert exceptions.raises[falcon.HTTPUnauthorized](
        lambda: auth_evaluator.evaluate(request, handler)
    )


@fact
def evaluate_handler_claims_are_forwarded_to_evaluator() -> None:
    token_evaluator = _StubTokenEvaluator(result=True)

    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=token_evaluator,
        basic_token_evaluator=None,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={'X-API-Key': 'any-key'}))
    handler = _DummyHandler()
    handler.__reshut_allow = [('role', 'admin')]
    handler.__reshut_deny = [('blocked', True)]
    handler.__reshut_require = [('active', True)]

    auth_evaluator.evaluate(request, handler)

    assert len(token_evaluator.calls) == 1
    token, deny, allow, require = token_evaluator.calls[0]
    assert token == 'any-key'
    assert deny == handler.__reshut_deny
    assert allow == handler.__reshut_allow
    assert require == handler.__reshut_require

@fact
def when_missing_authorization_then_fail() -> None:
    token_evaluator = _StubTokenEvaluator(result=True)

    auth_evaluator = AuthorizationEvaluator(
        apikey_token_evaluator=token_evaluator,
        basic_token_evaluator=None,
        bearer_token_evaluator=None,
    )
    request = cast(falcon.Request, _DummyRequest(headers={}))
    handler = _DummyHandler()

    assert exceptions.raises[falcon.HTTPBadRequest](
        lambda: auth_evaluator.evaluate(request, handler)
    )
