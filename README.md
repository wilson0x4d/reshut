
[![reshut on PyPI](https://img.shields.io/pypi/v/reshut.svg)](https://pypi.org/project/reshut/) [![reshut on readthedocs](https://readthedocs.org/projects/reshut/badge/?version=latest)](https://reshut.readthedocs.io)

**reshut** (רשות) is a decorative auth library for [Falcon](https://falconframework.org/).

This README is only a high-level introduction to **reshut**. For more detailed documentation, please view the official docs at [https://reshut.readthedocs.io](https://reshut.readthedocs.io).


## Features

- **Decorators** that allow or deny access based on auth‑token claims; extensible to fine‑grained levels when required.
- **ASGI and WSGI middleware** for authorization, configurable and able to run multiple side‑by‑side configurations.
- **Header handling** for `Authorization` and `X-API-Key` headers; exposing Bearer, API‑key, and Basic auth schemes.
- **Supported algorithms**: HMAC (SHA‑256/384/512), RSA (2048, 3072, ≥ 4096 bits), ECDSA (P‑256, P‑384, P‑512), and EdDSA (Ed25519, Ed448).
- **JWK implementation** for secure key transmission.
- **Utility functions** for key generation, claim tokenization, and token validation, plus equivalent CLI tools for dev/QA/ops use.


## Installation

You can install `reshut` from [PyPI](https://pypi.org/project/reshut/) through usual means, such as `pip`:

```bash
    pip install reshut
```


## Usage

To use `reshut` two things must be done; first you must add an authorization middleware, and second you must apply one or more authorization decorators to a request handler. Consider the following example:

```python

    import falcon.asgi as asgi
    from reshut import Algorithm, middleware, utils
    from .api.v3.FakeApi import FakeApi

    # you create a falcon app
    app = asgi.App()
    # you register the middleware, which applies Authorization checks to ALL requests
    symmetric_key = utils.keygen(Algorithm.HS256)
    asymmetric_key = utils.keygen(Algorithm.ED448)
    app.add_middleware(middleware.AsgiAuthorizationMiddleware(
        apikey_evaluater=middleware.TokenEvaluator(symmetric_key),
        bearer_evaluater=middleware.TokenEvaluator(asymmetric_key)
    ))
    # you add some routes to your app
    app.add_route('/api/v3/fakes', api.v3.FakeApi())
    app.add_route('/api/v3/fakes/{id:int}', api.v3.FakeApi())
```

Elsewhere in your project, you defined `FakeApi` and decorated at least one handler to customize Authorization:

```python

    from reshut.authorization import allow_anonymous, allow_claim, deny_claim, require_claim

    class FakeApi:

        def initialize(self) -> None:
            pass

        # access granted to any caller:
        @allow_anonymous
        async def on_delete(self, id:str) -> None:
            pass

        # access denied to callers with `fake_restricted==yes`:
        @deny_claim('fake_restricted', 'yes')
        # access granted to callers having either `fake_reader` OR `fake_writer`:
        @allow_claim('fake_reader') 
        @allow_claim('fake_writer')
        async def on_get(self, id:str) -> None:
            pass

        # access granted to callers having `roles` claim, where one
        # of the roles is "ADMIN", performed via `ClaimEvaluator` callback:
        @allow_claim('roles', lambda roles: 'ADMIN' in roles)
        # access granted to callers having `readonly_user` with a `False` value:
        @allow_claim('readonly_user', False)
        async def on_put(self, id:str) -> None:
            pass

        # access granted to callers having BOTH `department_id` of 123, 234, or 345
        # and-also having `can_create==True`:
        @require_claim('department_id', lambda x: x in [123,234,345])
        @require_claim('can_create', True)
        async def on_post(self, id:str) -> None:
            pass
```

**In the example above:**

- `@allow_anonymous` – grants access to every caller, whether authenticated or not.
- `@allow_claim` – lists the claims that *may* grant access; **at least one** of the listed claims must be present in the request.
- `@deny_claim` – lists the claims that *will* deny access if they appear in the request.
- `@require_claim` – lists the claims that *must* be present for access to be granted; **all** of the specified claims must be satisfied, otherwise access is denied.

All authorization decorators optionally allow matching a specific literal value or a Claim Evaluator function (seen in the example above as `lambda` syntax.)

Claim Evaluator functions are useful for checking complex claim types like dates, dicts, lists, etc. while literal values are useful for checking well-known/individual values.


## Generating Keys, Tokenizing Claims, and Validating Tokens

**reshut** provides both CLI tools (bash scripts) and Python utilities (functions).

### via `bash`

```bash
    # PREPARE: you can either pull the git repo
    git clone https://github.com/wilson0x4d/reshut.git
    cd reshut
    source .scripts/init-venv

    # PREPARE: or you can pull the PyPI package
    mkdir workspace
    cd workspace
    python -m venv venv-reshut
    venv-reshut/bin/activate
    pip install reshut

    # `reshut-keygen` generates PRIVATE KEYS only to be
    # used by you or your organization. they are NOT
    # meant for sharing with a third party.

    # generate an hs256 secret, output is written
    # to a single "my_symmetric_key.jwk" file:
    reshut-keygen --type HS256 --output my_symmetric_key

    # generate an rs256 keypair, outputs are written
    # to a single "my_asymmetric_key.jwk":
    reshut-keygen --type RS256 --output my_asymmetric_key

    # in the above examples, the `--output` argument may
    # specify a path; absolute or relative, where the last
    # part of the path is always taken as a filename base.

    # `reshut-tokenize` creates a SHARED TOKEN meant to
    # be provided to a third party such as developers, testers,
    # or business partners/integrators for auth purposes:
    reshut-tokenize --key key.jwk --claims '{"foo":"bar"}'

    # (the token will be printed to stdout)

    # `reshut-validate` accepts a key and a token:
    reshut-validate --key key.jwk --token 'the_token'

    # (the claims will be printed to stdout)
```

### via Python
In a Python script you can import utility functions from the ``reshut.utils`` namespace to generate keys, tokenize claims, and validate tokens.

```python
    from reshut import Algorithm, utils

    # generate keys:
    ed448_key = utils.keygen(Algorithm.ED448)
    print(ed448_key)

    # tokenize claims:
    token = utils.tokenize(
        ed448_key,
        {S
            'sub': 'Subject',
            'iss': 'Issuer'
        }
    )
    print(token)

    # validate a token:
    claims = utils.validate(ed448_key, token)
    print(claims)

    # individual claims can then be verified.  These examples
    # are only really useful if you are automating issuance,
    # are a third-party that needs to generate a token on-demand,
    # or are implementing a custom token validator.
```

## Contact

You can reach me on [Discord](https://discordapp.com/users/307684202080501761) or [open an Issue on Github](https://github.com/wilson0x4d/reshut/issues/new/choose).
