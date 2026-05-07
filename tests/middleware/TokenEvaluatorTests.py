# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import falcon
from punit import fact
from reshut.middleware import TokenEvaluator
from reshut.utils import Algorithm, keygen, tokenize


def __make_evaluator() -> tuple[TokenEvaluator, str]:
    secret, _ = keygen(Algorithm.HS256)
    evaluator = TokenEvaluator(Algorithm.HS256, secret)
    return evaluator, secret

@fact
def allow_claim_matching():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob'}

    token = tokenize(Algorithm.HS256, secret, claims)

    # allow_claims requires role == 'admin'
    allow = {'role': 'admin'}
    deny   = {}
    require = {}

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'Allowed claim should grant access'

@fact
def allow_claim_missing():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'user', 'user': 'bob'}

    token = tokenize(Algorithm.HS256, secret, claims)

    allow = {'role': 'admin'}   # we *require* admin, but token is just 'user'
    deny   = {}
    require = {}

    try:
        evaluator.evaluate(token, deny, allow, require)
        # If we get here, the test failed – an exception should have been raised
        assert False, 'Expected HTTPUnauthorized for missing ALLOW claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        # The description should be the one set for the ALLOW branch
        assert exc.description == 'ALLOW'
        assert exc.title == 'Authorization Disallowed'

@fact
def deny_claim_exact_match():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'blocked': True}

    token = tokenize(Algorithm.HS256, secret, claims)

    deny = {'blocked': True}    # any token with blocked=True must be denied
    allow = {}
    require = {}

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for DENY rule' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'

@fact
def deny_claim_custom_evaluator():
    from typing import Callable
    from reshut.authorization import ClaimEvaluator

    # A simple evaluator that denies any numeric claim > 10
    class GreaterThanTen(ClaimEvaluator):
        def __call__(self, value) -> bool:      # return True = match → deny
            return isinstance(value, (int, float)) and value > 10

    evaluator, secret = __make_evaluator()
    claims = {'score': 42}

    token = tokenize(Algorithm.HS256, secret, claims)

    deny = {'score': GreaterThanTen()}
    allow = {}
    require = {}

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for custom DENY evaluator' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'

@fact
def require_claim_missing():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin'}

    token = tokenize(Algorithm.HS256, secret, claims)

    require = {'user': 'bob'}   # token does not contain 'user'
    deny = {}
    allow = {}

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for missing REQUIRE claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'

@fact
def require_claim_wrong_value():
    evaluator, secret = __make_evaluator()
    claims = {'user': 'alice'}

    token = tokenize(Algorithm.HS256, secret, claims)

    require = {'user': 'bob'}   # wrong value
    deny = {}
    allow = {}

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Expected HTTPUnauthorized for mismatched REQUIRE claim' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'

@fact
def require_claim_success():
    from reshut.authorization import ClaimEvaluator

    class StartsWithA(ClaimEvaluator):
        def __call__(self, value) -> bool:
            return isinstance(value, str) and value.startswith('A')

    evaluator, secret = __make_evaluator()
    claims = {'user': 'Alice'}

    token = tokenize(Algorithm.HS256, secret, claims)

    require = {'user': StartsWithA()}
    deny = {}
    allow = {}

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'Required claim should allow access'

@fact
def full_flow_success():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob', 'dept': 'sales'}

    token = tokenize(Algorithm.HS256, secret, claims)

    deny = {'blocked': False}                # not present → no deny
    require = {'role': 'admin'}              # matches
    allow = {'dept': 'sales', 'user': 'bob'} # at least one matches (both do)

    result = evaluator.evaluate(token, deny, allow, require)
    assert result is True, 'All rules satisfied – should be granted'

@fact
def full_flow_deny_overrides():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin', 'user': 'bob'}

    token = tokenize(Algorithm.HS256, secret, claims)

    deny = {'user': 'bob'}      # this matches → immediate denial
    require = {'role': 'admin'}
    allow = {'role': 'admin'}

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'DENY rule should override ALLOW/REQUIRE' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'DENY'
        assert exc.title == 'Authorization Denied'

@fact
def full_flow_require_missing_overrides():
    evaluator, secret = __make_evaluator()
    claims = {'role': 'admin'}   # missing required 'user'

    token = tokenize(Algorithm.HS256, secret, claims)

    deny = {}
    require = {'user': 'bob'}    # missing → denial
    allow = {'role': 'admin'}    # would match, but require fails first

    try:
        evaluator.evaluate(token, deny, allow, require)
        assert False, 'Missing REQUIRE should deny even if ALLOW matches' # pragma: no cover
    except falcon.HTTPUnauthorized as exc:
        assert exc.description == 'REQUIRE'
        assert exc.title == 'Authorization Missing'
