
[![reshut on PyPI](https://img.shields.io/pypi/v/reshut.svg)](https://pypi.org/project/reshut/) [![reshut on readthedocs](https://readthedocs.org/projects/reshut/badge/?version=latest)](https://reshut.readthedocs.io)

**reshut** (רשות) is a decorative auth library for [Falcon](https://falconframework.org/).

This README is only a high-level introduction to **reshut**. For more detailed documentation, please view the official docs at [https://reshut.readthedocs.io](https://reshut.readthedocs.io).

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

In the above example:

`@allow_anonymous` will grant access to all callers, authenticated or not.

`@allow_claim` specifies which claims will grant access, at least one of them must be satisfied by the request.

`@deny_claim` specifies which claims will deny access.

`@require_claim` specifies which claims are required for "access granted", ALL specified claims must be satisfied by the request or access is denied.

All authorization decorators optionally allow matching a specific literal value or a Claim Evaluator function (seen in the example above as `lambda` syntax.)

Claim Evaluator functions are useful for checking complex claim types like dates, dicts, lists, etc. while literal values are useful for checking well-known/individual values.

## Generating Keys, Tokenizing Claims, and Validating Tokens

If you want to manually generate keys there is a CLI tool `reshut-keygen` you can use, convenient for developers, testers, and CI/CD pipelines that need ephemeral test assets:

```bash
# these generate PRIVATE KEYS only to be used
# by you or your organization. they are NOT to be
# shared with a third party.

# generate an hs256 secret, output is written
# to a single "my_symmetric_key.jwk" file
reshut-keygen --type HS256 --output my_symmetric_key

# generate an rs256 keypair, outputs are written
# to a single "my_asymmetric_key.jwk"
reshut-keygen --type RS256 --output my_asymmetric_key

# the --output arg may specify a path, the last
# part of the path is always taken as a filename base.
```

There is also a `reshut-tokenize` tool you can use to tokenize claims:

```bash
    # this generates a token meant to be provided
    # to a third party such as developers, testers,
    # or business partners/integrators for authorization.
    reshut-tokenize --key key.jwk --claims '{"foo":"bar"}'
    # the token will be printed to stdout
```

Lastly, there is a `reshut-validate` tool you can use to validate tokens:

```bash
    reshut-validate --key key.jwk --token 'the_token'
    # the claims will be formatted as JSON and printed to stdout
```

These tools are written using the `reshut.utils` namespace, you can use the utils namespace within your own code to dynamically allocate keys and tokens as you see fit for your solution (instead of dropping to a shell for the same result).

For example, here is a snippet demonstrating the generation of an ed448 keypair and-also an ed448 token valid for that keypair:

```python

from reshut.utils import Algorithm, keygen, tokenize, validate

# on the server/etc, generate keys
ed448_key = keygen(Algorithm.ED448)
print(ed448_key)

# on the server/etc, issue "secure" claims (claims the recipient can see/verify, but cannot modify)
token = tokenize(ed448_key, {
    sub: 'Subject',
    iss: 'Issuer',
    exp: datetime.now()+timedelta(days=90)
})
print(token)

claims = validate(ed448_key.pub, token)
print(claims)

# individual claims can then be verified.  these examples are only really useful
# if you are automating key issuance, token issuance, are a third-party that
# needs to generate a complex/symmetric token on-demand, or are implementing
# a custom token validator.
```

## Contact

You can reach me on [Discord](https://discordapp.com/users/307684202080501761) or [open an Issue on Github](https://github.com/wilson0x4d/reshut/issues/new/choose).
