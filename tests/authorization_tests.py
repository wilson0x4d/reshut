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
