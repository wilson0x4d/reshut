# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import falcon
from typing import Any, Optional, cast
from ..authorization import ClaimEvaluator
from .TokenEvaluator import TokenEvaluator


class AuthorizationEvaluator:
    """
    Evaluates the authorization data in a request against the authorization requirements of a resource handler.
    """

    __apikey_token_evaluator:Optional[TokenEvaluator]
    __basic_token_evaluator:Optional[TokenEvaluator]
    __bearer_token_evaluator:Optional[TokenEvaluator]

    def __init__(
            self,
            apikey_token_evaluator:Optional[TokenEvaluator] = None,
            basic_token_evaluator:Optional[TokenEvaluator] = None,
            bearer_token_evaluator:Optional[TokenEvaluator] = None
        ) -> None:
        self.__apikey_token_evaluator = apikey_token_evaluator
        self.__basic_token_evaluator = basic_token_evaluator
        self.__bearer_token_evaluator = bearer_token_evaluator      

    def evaluate(self, req:falcon.Request, handler:Any) -> None:
        """
        Evaluate authorization data in ``req`` against authorization requirements of ``handler``.

        :raises falcon.HTTPBadRequest: When the request has missing or invalid Authorization data.
        :raises falcon.HTTPUnauthorized: When claim rule checks fail.
        """
        scheme:str|None = None
        token:str|None = None
        deny_claims = {} if not hasattr(handler, '__reshut_deny') else cast(dict[str,str|ClaimEvaluator], getattr(handler, '__reshut_deny'))
        allow_claims = {} if not hasattr(handler, '__reshut_allow') else cast(dict[str,str|ClaimEvaluator], getattr(handler, '__reshut_allow'))
        require_claims = {} if not hasattr(handler, '__reshut_require') else cast(dict[str,str|ClaimEvaluator], getattr(handler, '__reshut_require'))
        # check for Authorization header
        authorization = req.get_header('Authorization', False, None)
        if authorization is not None:
            scheme, token = authorization.split(' ', 1)
            scheme = scheme.lower()
        else:
            # check for X-API-Key header
            token = req.get_header('X-API-Key', False, None)
            if token is not None and len(token) > 0:
                scheme = 'apikey'
        if scheme is None or token is None:
            raise falcon.HTTPBadRequest(
                title='Authorization Required',
                description=f'Missing Authorization',
            )
        match scheme:
            case 'apikey':
                if self.__apikey_token_evaluator is not None and self.__apikey_token_evaluator.evaluate(token, deny_claims, allow_claims, require_claims):
                    return
            case 'basic':
                if self.__basic_token_evaluator is not None and self.__basic_token_evaluator.evaluate(token, deny_claims, allow_claims, require_claims):
                    return
            case 'bearer':
                if self.__bearer_token_evaluator is not None and self.__bearer_token_evaluator.evaluate(token, deny_claims, allow_claims, require_claims):
                    return
            case _:
                raise falcon.HTTPBadRequest(
                    title='Authorization Unsupported',
                    description=f'Scheme "{scheme}" not supported.',
                )
        # reject.
        if self.__apikey_token_evaluator is not None or self.__basic_token_evaluator is not None or self.__bearer_token_evaluator is not None:
            raise falcon.HTTPUnauthorized(
                title='Authorization Failed',
                description='Unsuccessful',
            )


__all__ = [
    'AuthorizationEvaluator'
]