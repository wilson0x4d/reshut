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

    decorator = allow_claim('foo', 'bar')
    decorated_func = decorator(target_func)
    assert target_func is decorated_func

@fact
def allow_claim_is_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = allow_claim('foo', 'bar')(target_func)
    decorated_func = allow_claim('shaun', 'wilson')(decorated_func)
    
    assert hasattr(decorated_func, '__reshut_allow'), 'missing expected attribute'
    assert len(getattr(decorated_func, '__reshut_allow')) == 2, 'ALLOW claims have wrong count'


@fact
def deny_claim_does_not_wrap() -> None:
    def target_func():
        pass # pragma: no cover

    decorator = deny_claim('foo', 'bar')
    decorated_func = decorator(target_func)
    assert target_func is decorated_func


@fact
def deny_claim_is_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = deny_claim('foo', 'bar')(target_func)
    decorated_func = deny_claim('shaun', 'wilson')(decorated_func)
    
    assert hasattr(decorated_func, '__reshut_deny'), 'missing expected attribute'
    assert len(getattr(decorated_func, '__reshut_deny')) == 2, 'DENY claims have wrong count'


@fact
def require_claim_does_not_wrap() -> None:
    def target_func():
        pass # pragma: no cover

    decorator = require_claim('foo', 'bar')
    decorated_func = decorator(target_func)
    assert target_func is decorated_func

@fact
def require_claim_is_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = require_claim('foo', 'bar')(target_func)
    decorated_func = require_claim('shaun', 'wilson')(decorated_func)
    
    assert hasattr(decorated_func, '__reshut_require'), 'missing expected attribute'
    assert len(getattr(decorated_func, '__reshut_require')) == 2, 'REQUIRE claims have wrong count'


@fact
def allow_claim_same_name_different_checks_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = allow_claim('scope', 'read')(target_func)
    decorated_func = allow_claim('scope', 'write')(decorated_func)
    
    assert hasattr(decorated_func, '__reshut_allow'), 'missing expected attribute'
    allow_rules = getattr(decorated_func, '__reshut_allow')
    assert len(allow_rules) == 2, 'ALLOW claims should have 2 entries'
    assert allow_rules[0] == ('scope', 'read'), 'first entry mismatch'
    assert allow_rules[1] == ('scope', 'write'), 'second entry mismatch'


@fact
def deny_claim_same_name_different_checks_cumulative() -> None:
    def target_func():
        pass # pragma: no cover

    decorated_func = deny_claim('scope', 'read')(target_func)
    decorated_func = deny_claim('scope', 'write')(decorated_func)
    
    assert hasattr(decorated_func, '__reshut_deny'), 'missing expected attribute'
    deny_rules = getattr(decorated_func, '__reshut_deny')
    assert len(deny_rules) == 2, 'DENY claims should have 2 entries'
    assert deny_rules[0] == ('scope', 'read'), 'first entry mismatch'
    assert deny_rules[1] == ('scope', 'write'), 'second entry mismatch'


@fact
def decorator_syntax_allow_claim_works() -> None:
    @allow_claim('scope', 'read')
    def target_func():
        pass

    assert hasattr(target_func, '__reshut_allow'), 'missing __reshut_allow when using decorator syntax'
    allow_rules = getattr(target_func, '__reshut_allow')
    assert len(allow_rules) == 1, 'ALLOW claims wrong count with decorator syntax'
    assert allow_rules[0] == ('scope', 'read'), 'decorator syntax claim mismatch'


@fact
def decorator_syntax_deny_claim_works() -> None:
    @deny_claim('scope', 'admin')
    def target_func():
        pass

    assert hasattr(target_func, '__reshut_deny'), 'missing __reshut_deny when using decorator syntax'
    deny_rules = getattr(target_func, '__reshut_deny')
    assert len(deny_rules) == 1, 'DENY claims wrong count with decorator syntax'
    assert deny_rules[0] == ('scope', 'admin'), 'decorator syntax deny claim mismatch'


@fact
def decorator_syntax_require_claim_works() -> None:
    @require_claim('role', 'admin')
    def target_func():
        pass

    assert hasattr(target_func, '__reshut_require'), 'missing __reshut_require when using decorator syntax'
    require_rules = getattr(target_func, '__reshut_require')
    assert len(require_rules) == 1, 'REQUIRE claims wrong count with decorator syntax'
    assert require_rules[0] == ('role', 'admin'), 'decorator syntax require claim mismatch'


@fact
def decorator_syntax_combined_works() -> None:
    @allow_claim('scope', 'read')
    @deny_claim('scope', 'admin')
    @require_claim('user_id')
    def target_func():
        pass

    allow_rules = getattr(target_func, '__reshut_allow')
    deny_rules = getattr(target_func, '__reshut_deny')
    require_rules = getattr(target_func, '__reshut_require')

    assert len(allow_rules) == 1 and allow_rules[0] == ('scope', 'read'), 'allowed claim mismatch'
    assert len(deny_rules) == 1 and deny_rules[0] == ('scope', 'admin'), 'denied claim mismatch'
    assert len(require_rules) == 1 and require_rules[0] == ('user_id', None), 'required claim mismatch'
