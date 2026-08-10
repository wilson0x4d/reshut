# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import falcon
from typing import Any, cast

from ..authorization import ClaimEvaluator
from ..jwk import JWK
from ..utils import validate


class TokenEvaluator:
    """
    Evaluates a token given an Algorithm and Key.
    """

    __key: JWK

    def __init__(self, key: JWK) -> None:
        self.__key = key

    def evaluate(
        self,
        token: str,
        deny_claims: list[tuple[str, Any]],
        allow_claims: list[tuple[str, Any]],
        require_claims: list[tuple[str, Any]]
    ) -> bool:
        """
        Evaluate a token against the supplied claim rules.

        :param token: The token to be evaluated.
        :param deny_claims: Claim DENY rules.
        :param allow_claims: Claim ALLOW rules.
        :param require_claims: Claim REQUIRE rules.
        :raises falcon.HTTPUnauthorized: When claim rule checks fail.
        :return: A boolean indicating success or failure, on failure the calling code should raise an appopriate exception.
        """
        claims = validate(self.__key, token)
        # check for denied claims (if any match, access denied)
        for k, claim_check in deny_claims:
            claim_value = claims.get(k, None)
            if claim_value is not None and (claim_check is None or claim_value == claim_check or (callable(claim_check) and cast(ClaimEvaluator, claim_check)(claim_value))):
                # access denied
                raise falcon.HTTPUnauthorized(
                    title='Authorization Denied',
                    description='DENY'
                )
        # check for required claims (if any not present, access denied]
        for k, claim_check in require_claims:
            claim_value = claims.get(k, None)
            if claim_value is None or (claim_check is not None and (claim_value != claim_check and (not callable(claim_check) or not cast(ClaimEvaluator, claim_check)(claim_value)))):
                # access denied
                raise falcon.HTTPUnauthorized(
                    title='Authorization Missing',
                    description='REQUIRE'
                )
        # check for allowed claims (if none match, access denied)
        if allow_claims:
            for k, claim_check in allow_claims:
                claim_value = claims.get(k, None)
                if claim_value is not None and (claim_check is None or claim_value == claim_check or (callable(claim_check) and cast(ClaimEvaluator, claim_check)(claim_value))):
                    # access granted
                    return True
            # access denied
            raise falcon.HTTPUnauthorized(
                title='Authorization Disallowed',
                description='ALLOW'
            )
        # access granted
        return True


__all__ = ['TokenEvaluator']
