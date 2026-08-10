# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from datetime import datetime, timedelta, timezone
import uuid
from punit import fact, theory, inlinedata, collections, exceptions
import falcon
from reshut.jwk import JWK
from reshut.utils import Algorithm, keygen, tokenize, validate
from typing import cast


@theory
@inlinedata(Algorithm.HS256)
@inlinedata(Algorithm.HS384)
@inlinedata(Algorithm.HS512)
@inlinedata(Algorithm.RS256)
@inlinedata(Algorithm.RS384)
@inlinedata(Algorithm.RS512)
@inlinedata(Algorithm.ES256)
@inlinedata(Algorithm.ES384)
@inlinedata(Algorithm.ES512)
@inlinedata(Algorithm.ED25519)
@inlinedata(Algorithm.ED448)
def utils_bvt(algorithm: Algorithm) -> None:
    """
    For the supplied *algorithm*:

    1. Generate a key (or key-pair) with ``keygen``.
    2. Encode a static claims dictionary with ``tokenize``.
    3. Decode the resulting JWT with ``validate``.
    4. Assert that the decoded claims are identical to the original claims.
    """
    key = keygen(algorithm)

    expected_claims = {
        'sub': '1234567890',
        'name': 'Alice Example',
        'admin': False,
        'iat': 1700000000,
    }

    token = tokenize(key, expected_claims)

    actual_claims = validate(key, token)

    assert collections.hasLength(actual_claims, len(expected_claims))

    assert collections.areSame(
        actual_claims,
        expected_claims,
        sort=True
    ), f'Algorithm {algorithm!s}: decoded claims differ from the original'


@fact
def keygen_when_invalid_algo_then_raise_NotImplementedError() -> None:
    assert exceptions.raises[NotImplementedError](lambda: keygen(cast(Algorithm, 'invalid')))


@fact
def tokenize_when_mismatched_audience_then_raise_Exception() -> None:
    expected_value = uuid.uuid4().hex
    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, audience=expected_value)
    claims = validate(key, token)
    assert exceptions.raises[falcon.HTTPUnauthorized](lambda: validate(key, token, audience='not-matching-audience'))


@fact
def tokenize_when_mismatched_issuer_then_raise_Exception() -> None:
    expected_value = uuid.uuid4().hex
    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, issuer=expected_value)
    claims = validate(key, token)
    assert exceptions.raises[falcon.HTTPUnauthorized](lambda: validate(key, token, issuer='not-matching-issuer'))


@fact
def tokenize_when_mismatched_subject_then_raise_Exception() -> None:
    expected_value = uuid.uuid4().hex
    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, subject=expected_value)
    claims = validate(key, token)
    assert exceptions.raises[falcon.HTTPUnauthorized](lambda: validate(key, token, subject='not-matching-audience'))


@fact
def tokenize_when_before_nbt_then_raise_Exception() -> None:
    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, not_before=int((datetime.now(timezone.utc)+timedelta(days=1)).timestamp()))
    assert exceptions.raises[falcon.HTTPUnauthorized](lambda: validate(key, token))


@fact
def tokenize_can_inject_audience() -> None:
    expected_value = uuid.uuid4().hex
    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, audience=expected_value)
    claims = validate(key, token)
    assert claims.get('aud', None) == expected_value, f'resulting token did not have expected `aud` claim: {claims}'


@fact
def tokenize_can_inject_issuer() -> None:
    expected_value = uuid.uuid4().hex
    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, issuer=expected_value)
    claims = validate(key, token)
    assert claims.get('iss', None) == expected_value, f'resulting token did not have expected `iss` claim: {claims}'


@theory
@inlinedata(True, True, True, True, True, True)
@inlinedata(True, True, True, True, True, False)
@inlinedata(True, True, True, True, False, False)
@inlinedata(True, True, True, False, False, False)
@inlinedata(True, True, False, False, False, False)
@inlinedata(True, False, False, False, False, False)
@inlinedata(False, False, False, False, False, False)
def standard_claims_unenforced(iss:bool, sub:bool, aud:bool, exp:bool, iat:bool, jti:bool) -> None:
    """
    runs permutations of "standard" claims to verify expected functionality
    """
    enforce:bool = False
    issuer:str|None = uuid.uuid4().hex if iss else None
    subject:str|None = uuid.uuid4().hex if sub else None
    audience:str|None = uuid.uuid4().hex if aud else None
    expiry:int|None = int((datetime.now(timezone.utc)+timedelta(days=1)).timestamp()) if exp else None
    issued_at:int|None = int(datetime.now(timezone.utc).timestamp()) if iat else None
    token_id:str|None = uuid.uuid4().hex if jti else None

    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, issuer=issuer, subject=subject, audience=audience, expiry=expiry, issued_at=issued_at, token_id=token_id)
    claims = validate(key, token, enforce=enforce, audience=audience, issuer=issuer, subject=subject)
    assert not iss or claims.get('iss') == issuer
    assert not sub or claims.get('sub') == subject
    assert not aud or claims.get('aud') == audience
    assert not exp or claims.get('exp') == expiry
    assert claims.get('iat') is not None and (not iat or claims.get('iat') == issued_at)
    assert not jti or claims.get('jti') == token_id


@theory
@inlinedata(True, True, True, True, True, True)
@inlinedata(True, True, True, True, True, False)
@inlinedata(True, True, True, True, False, False)
@inlinedata(True, True, True, False, False, False)
@inlinedata(True, True, False, False, False, False)
@inlinedata(True, False, False, False, False, False)
@inlinedata(False, False, False, False, False, False)
def standard_claims_enforced(iss:bool, sub:bool, aud:bool, exp:bool, iat:bool, jti:bool) -> None:
    """
    runs permutations of "standard" claims to verify expected functionality
    """
    enforce:bool = True
    issuer:str|None = uuid.uuid4().hex if iss else None
    subject:str|None = uuid.uuid4().hex if sub else None
    audience:str|None = uuid.uuid4().hex if aud else None
    expiry:int|None = int((datetime.now(timezone.utc)+timedelta(days=1)).timestamp()) if exp else None
    issued_at:int|None = int(datetime.now(timezone.utc).timestamp()) if iat else None
    token_id:str|None = uuid.uuid4().hex if jti else None

    key = keygen(Algorithm.HS256)
    token = tokenize(key, { 'foo': 'bar'}, issuer=issuer, subject=subject, audience=audience, expiry=expiry, issued_at=issued_at, token_id=token_id)
    claims = validate(key, token, enforce=enforce, audience=audience, issuer=issuer, subject=subject)
    assert not iss or claims.get('iss') == issuer
    assert not sub or claims.get('sub') == subject
    assert not aud or claims.get('aud') == audience
    assert not exp or claims.get('exp') == expiry
    assert claims.get('iat') is not None and (not iat or claims.get('iat') == issued_at)
    assert not jti or claims.get('jti') == token_id
