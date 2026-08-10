# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import falcon
from punit import fact
from reshut.authorization import ClaimEvaluator
from reshut.jwk import JWK
from reshut.middleware import TokenEvaluator
from reshut.utils import Algorithm, keygen, tokenize
from typing import Any, cast

def __make_evaluator() -> tuple[TokenEvaluator, JWK]:
    key = keygen(Algorithm.HS256)
    evaluator = TokenEvaluator(key)
    return evaluator, key


@fact
def allow_claim_matching() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob'}

    token = tokenize(secret, claims)

    # allow_claims requires role == 'admin'
    allow: list[tuple[str, Any]] = [('role', 'admin')]
    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'Allowed claim should grant access'


@fact
def allow_claim_missing() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'user', 'user': 'bob'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = [('role', 'admin')]
    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        # If we get here, the test failed – an exception should have been raised
        assert False, 'Expected HTTPUnauthorized for missing ALLOW claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        # The description should be the one set for the ALLOW branch
        assert exc.description == 'ALLOW'
        assert exc.title == 'Authorization Disallowed'


@fact
def deny_claim_exact_match() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'blocked': True}

    token = tokenize(secret, claims)

    deny: list[tuple[str, Any]] = [('blocked', True)]
    allow: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for DENY rule' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'


@fact
def deny_claim_custom_evaluator() -> None:
    from typing import Callable

    # A simple evaluator that denies any numeric claim > 10
    class GreaterThanTen:
        def __call__(self, value) -> bool:      # return True = match → deny
            return isinstance(value, (int, float)) and value > 10

    evaluator, secret = __make_evaluator()
    claims = {'score': 42}

    token = tokenize(secret, claims)

    deny: list[tuple[str, Any]] = cast(list[tuple[str, Any]], [('score', GreaterThanTen())])
    allow: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for custom DENY evaluator' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'


@fact
def require_claim_missing() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin'}

    token = tokenize(secret, claims)

    require: list[tuple[str, Any]] = [('user', 'bob')]
    deny: list[tuple[str, Any]] = []
    allow: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for missing REQUIRE claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'


@fact
def require_claim_wrong_value() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'user': 'alice'}

    token = tokenize(secret, claims)

    require: list[tuple[str, Any]] = [('user', 'bob')]
    deny: list[tuple[str, Any]] = []
    allow: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for mismatched REQUIRE claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'


@fact
def require_claim_success() -> None:
    from reshut.authorization import ClaimEvaluator

    class StartsWithA:
        def __call__(self, value) -> bool:
            return isinstance(value, str) and value.startswith('A')

    evaluator, secret = __make_evaluator()
    claims = {'user': 'Alice'}

    token = tokenize(secret, claims)

    require: list[tuple[str, Any]] = cast(list[tuple[str, Any]], [('user', StartsWithA())])
    deny: list[tuple[str, Any]] = []
    allow: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'Required claim should allow access'


@fact
def full_flow_success() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob', 'dept': 'sales'}

    token = tokenize(secret, claims)

    deny: list[tuple[str, Any]] = [('blocked', False)]
    require: list[tuple[str, Any]] = [('role', 'admin')]
    allow: list[tuple[str, Any]] = [('dept', 'sales'), ('user', 'bob')]

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'All rules satisfied – should be granted'


@fact
def full_flow_deny_overrides() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob'}

    token = tokenize(secret, claims)

    deny: list[tuple[str, Any]] = [('user', 'bob')]
    require: list[tuple[str, Any]] = [('role', 'admin')]
    allow: list[tuple[str, Any]] = [('role', 'admin')]

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'DENY rule should override ALLOW/REQUIRE' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'


@fact
def full_flow_require_missing_overrides() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin'}   # missing required 'user'

    token = tokenize(secret, claims)

    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = [('user', 'bob')]
    allow: list[tuple[str, Any]] = [('role', 'admin')]

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Missing REQUIRE should deny even if ALLOW matches' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'


@fact
def allow_claim_same_name_multiple_checks_cumulative() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'scope': 'read-only'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = [('scope', 'read-only'), ('scope', 'read-write')]
    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'First matching scope should grant access'


@fact
def allow_claim_same_name_no_match() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'scope': 'delete'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = [('scope', 'read-only'), ('scope', 'read-write')]
    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Non-matching scope should deny access' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'ALLOW'
        assert exc.title == 'Authorization Disallowed'


@fact
def deny_claim_same_name_multiple_checks_cumulative() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'scope': 'read-only'}

    token = tokenize(secret, claims)

    deny: list[tuple[str, Any]] = [('scope', 'write-only'), ('scope', 'read-only')]
    allow: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Matching scope should deny access' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'


@fact
def allow_claim_check_none_present() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'fake_reader': 'any_value_at_all'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = [('fake_reader', None)]
    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'ALLOW with check=None should match when claim is present'


@fact
def allow_claim_check_none_missing() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'other_claim': 'value'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = [('fake_reader', None)]
    deny: list[tuple[str, Any]] = []
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for missing ALLOW claim with check=None' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'ALLOW'
        assert exc.title == 'Authorization Disallowed'


@fact
def deny_claim_check_none_present() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'blocked_claim': 'any_value'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = []
    deny: list[tuple[str, Any]] = [('blocked_claim', None)]
    require: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for DENY with check=None and present claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'


@fact
def deny_claim_check_none_missing() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'other_claim': 'value'}

    token = tokenize(secret, claims)

    allow: list[tuple[str, Any]] = []
    deny: list[tuple[str, Any]] = [('blocked_claim', None)]
    require: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'DENY with check=None should not match when claim is absent'


@fact
def require_claim_check_none_present() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'some_role': 'anything_goes'}

    token = tokenize(secret, claims)

    require: list[tuple[str, Any]] = [('some_role', None)]
    deny: list[tuple[str, Any]] = []
    allow: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'REQUIRE with check=None should pass when claim is present'


@fact
def require_claim_check_none_missing() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'other_claim': 'value'}

    token = tokenize(secret, claims)

    require: list[tuple[str, Any]] = [('some_role', None)]
    deny: list[tuple[str, Any]] = []
    allow: list[tuple[str, Any]] = []

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for missing REQUIRE claim with check=None' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'


@fact
def require_claim_multiple_claims_any_match() -> None:
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob'}

    token = tokenize(secret, claims)

    require: list[tuple[str, Any]] = [('role', 'admin'), ('user', 'bob')]
    deny: list[tuple[str, Any]] = []
    allow: list[tuple[str, Any]] = []

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'All required claims must match'
