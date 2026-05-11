# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import falcon
from falcon._typing import AsgiMiddlewareWithProcessResource
import inspect
from typing import Any, Mapping, Optional, cast
from .AuthorizationEvaluator import AuthorizationEvaluator
from .TokenEvaluator import TokenEvaluator


class AsgiAuthorizationMiddleware(AsgiMiddlewareWithProcessResource):
    """
    ASGI-compatible Authorization Middleware

    ---
    Intercepts resource requests to apply Authorization logic.
    """

    __authorization_evaluator: AuthorizationEvaluator

    def __init__(
        self,
        apikey_token_evaluator: Optional[TokenEvaluator] = None,
        basic_token_evaluator: Optional[TokenEvaluator] = None,
        bearer_token_evaluator: Optional[TokenEvaluator] = None
    ) -> None:
        self.__authorization_evaluator = AuthorizationEvaluator(
            apikey_token_evaluator=apikey_token_evaluator,
            basic_token_evaluator=basic_token_evaluator,
            bearer_token_evaluator=bearer_token_evaluator
        )

    @property
    def supports_apikey(self) -> bool:
        return self.__authorization_evaluator.supports_apikey is True

    @property
    def supports_basic(self) -> bool:
        return self.__authorization_evaluator.supports_basic is True

    @property
    def supports_bearer(self) -> bool:
        return self.__authorization_evaluator.supports_bearer is True

    async def process_resource(
        self,
        req: falcon.Request,
        resp: falcon.Response,
        resource: object,
        params: Mapping[str, Any]
    ) -> None:
        """
        Intercept for ``process_resource`` that evaluates authorization data in the request against authorization requirements of the resource handler.
        """
        handler_name = f'on_{req.method.lower()}'
        handler = getattr(resource, handler_name, None)
        if handler is None:
            return
        handler = inspect.unwrap(cast(Any, handler))
        if getattr(handler, '__reshut_noauth', False):
            # access granted
            return
        self.__authorization_evaluator.evaluate(req, handler)


__all__ = ['AsgiAuthorizationMiddleware']
