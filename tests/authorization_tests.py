# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from punit import fact
from reshut.authorization import allow_anonymous, allow_claim, deny_claim, require_claim


@fact
def allow_anonymous_does_not_wrap() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = allow_anonymous(target_func)
    assert target_func is decorated_func


@fact
def allow_claim_does_not_wrap() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = allow_claim(target_func, 'foo', 'bar')
    assert target_func is decorated_func

@fact
def allow_claim_is_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = allow_claim(target_func, 'foo', 'bar')
    decorated_func = allow_claim(target_func, 'shaun', 'wilson')
    
    assert hasattr(decorated_func, '__reshut_allow'), 'missing expected attribute'
    assert len(getattr(decorated_func, '__reshut_allow')) == 2, 'ALLOW claims have wrong count'


@fact
def deny_claim_does_not_wrap() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = deny_claim(target_func, 'foo', 'bar')
    assert target_func is decorated_func


@fact
def deny_claim_is_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = deny_claim(target_func, 'foo', 'bar')
    decorated_func = deny_claim(target_func, 'shaun', 'wilson')
    
    assert hasattr(decorated_func, '__reshut_deny'), 'missing expected attribute'
    assert len(getattr(decorated_func, '__reshut_deny')) == 2, 'DENY claims have wrong count'


@fact
def require_claim_does_not_wrap() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = require_claim(target_func, 'foo', 'bar')
    assert target_func is decorated_func

@fact
def require_claim_is_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = require_claim(target_func, 'foo', 'bar')
    decorated_func = require_claim(target_func, 'shaun', 'wilson')
    
    assert hasattr(decorated_func, '__reshut_require'), 'missing expected attribute'
    assert len(getattr(decorated_func, '__reshut_require')) == 2, 'REQUIRE claims have wrong count'


@fact
def allow_claim_same_name_different_checks_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = allow_claim(target_func, 'scope', 'read')
    decorated_func = allow_claim(target_func, 'scope', 'write')
    
    assert hasattr(decorated_func, '__reshut_allow'), 'missing expected attribute'
    allow_rules = getattr(decorated_func, '__reshut_allow')
    assert len(allow_rules) == 2, 'ALLOW claims should have 2 entries'
    assert allow_rules[0] == ('scope', 'read'), 'first entry mismatch'
    assert allow_rules[1] == ('scope', 'write'), 'second entry mismatch'


@fact
def deny_claim_same_name_different_checks_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = deny_claim(target_func, 'scope', 'read')
    decorated_func = deny_claim(target_func, 'scope', 'write')
    
    assert hasattr(decorated_func, '__reshut_deny'), 'missing expected attribute'
    deny_rules = getattr(decorated_func, '__reshut_deny')
    assert len(deny_rules) == 2, 'DENY claims should have 2 entries'
    assert deny_rules[0] == ('scope', 'read'), 'first entry mismatch'
    assert deny_rules[1] == ('scope', 'write'), 'second entry mismatch'
