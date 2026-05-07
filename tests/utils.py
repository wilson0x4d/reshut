# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import uuid
from punit import fact, theory, inlinedata, collections, exceptions
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

    1. Generate a key (or key‑pair) with ``keygen``.
    2. Encode a static claims dictionary with ``tokenize``.
    3. Decode the resulting JWT with ``validate``.
    4. Assert that the decoded claims are identical to the original claims.
    """
    private_key, public_key = keygen(algorithm)

    # symmetric algorithms return only a shared secret, so use it as `public_key`
    if public_key is None:
        public_key = private_key

    expected_claims = {
        'sub': '1234567890',
        'name': 'Alice Example',
        'admin': False,
        'iat': 1700000000,          # a deterministic timestamp to avoid jitter
    }

    token = tokenize(algorithm, private_key, expected_claims)

    actual_claims = validate(algorithm, public_key, token)

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
    key, _ = keygen(Algorithm.HS256)
    token = tokenize(Algorithm.HS256, key, { 'foo': 'bar'}, audience=expected_value)
    claims = validate(Algorithm.HS256, key, token)
    assert exceptions.raises[Exception](lambda: validate(Algorithm.HS256, key, token, audience='not-matching-audience'))

@fact
def tokenize_when_mismatched_issuer_then_raise_Exception() -> None:
    expected_value = uuid.uuid4().hex
    key, _ = keygen(Algorithm.HS256)
    token = tokenize(Algorithm.HS256, key, { 'foo': 'bar'}, issuer=expected_value)
    claims = validate(Algorithm.HS256, key, token)
    assert exceptions.raises[Exception](lambda: validate(Algorithm.HS256, key, token, issuer='not-matching-issuer'))

@fact
def tokenize_can_inject_audience() -> None:
    expected_value = uuid.uuid4().hex
    key, _ = keygen(Algorithm.HS256)
    token = tokenize(Algorithm.HS256, key, { 'foo': 'bar'}, audience=expected_value)
    claims = validate(Algorithm.HS256, key, token)
    assert claims.get('aud', None) == expected_value, f'resulting token did not have expected `aud` claim: {claims}'

@fact
def tokenize_can_inject_issuer() -> None:
    expected_value = uuid.uuid4().hex
    key, _ = keygen(Algorithm.HS256)
    token = tokenize(Algorithm.HS256, key, { 'foo': 'bar'}, issuer=expected_value)
    claims = validate(Algorithm.HS256, key, token)
    assert claims.get('iss', None) == expected_value, f'resulting token did not have expected `iss` claim: {claims}'

@fact
def tokenize_fails_on_invaliud_algo() -> None:
    key, _ = keygen(Algorithm.HS256)
    assert exceptions.raises[Exception](lambda: tokenize(Algorithm.RS256, key, { 'foo': 'bar'}))
