---
name: reshut
description: Falcon JWT authorization library — decorator-based handler claims, ASGI/WSGI middleware, 11 crypto algorithms, full JWK support, token revocation, and CLI tools (keygen, tokenize, validate). Use when working with reshut decorators, middleware, JWK conversion, or JWT utilities.
user-invocable: true
disable-model-invocation: false
type: reference
---

# reshut — Falcon JWT Authorization

**reshut** (רשות — "permission") is a JWT-based authorization library for the Falcon web framework. It provides decorator-level handler claims, ASGI/WSGI middleware, 11 cryptographic algorithms, full JWK support, and CLI tools.

**Dependencies:** `falcon >= 4.2`, `pyjwt[crypto] >= 2.12.1`, `cryptography >= 48` (Python ≥ 3.11).

---

## 1. Authorization Decorators

Set claim rules on handler methods. Decorators are **non-wrapping** — they set attributes on the original function (discovered via `inspect.unwrap`).

```python
import falcon
from reshut.authorization import allow_anonymous, allow_claim, deny_claim, require_claim

class MyResource:
    @allow_anonymous
    def on_get(self, req, resp):
        resp.media = {"message": "public"}

    @require_claim("role", "admin")
    def on_post(self, req, resp):
        resp.media = {"status": "admin action"}

    @deny_claim("banned", True)
    def on_delete(self, req, resp):
        resp.media = {"status": "deleted"}

    @allow_claim("scope", "write")
    def on_patch(self, req, resp):
        resp.media = {"status": "updated"}
```

### Available decorators

| Decorator | Rule logic | When access is granted |
|-----------|-----------|----------------------|
| `@allow_anonymous` | Bypass | Always — no auth required |
| `@require_claim(name, check)` | AND | **Every** listed `(name, check)` pair evaluates to `True` — all claims must match |
| `@deny_claim(name, check)` | AND, OR | No listed claim evaluation returns `True` — any single match blocks access |
| `@allow_claim(name, check)` | OR | At least one listed claim evaluation returns `True` — if none match, access denied |

When multiple decorator rules apply to the same handler, they are evaluated in a fixed order — **DENY first, then REQUIRED, then ALLOW**. If a DENY rule matches access is blocked immediately regardless of other rules. So `@deny_claim('role', 'read-only')` blocks read-only users even if `@require_claim('role', 'admin')` passes (a read-only user will never have `role=admin`, but any admin who also carries `role=read-only` gets blocked).

### Claim evaluators

Each decorator takes `claim_name` and optional `claim_check`:

- **`None`** — claim just needs to be present in the token, any value accepts: `@allow_claim("authenticated")`
- **Literal value** — exact match: `@require_claim("role", "admin")`
- **Callable** (`ClaimEvaluator = Callable[[Any], bool]`) — custom logic:
  ```python
  from datetime import datetime, timezone
  from reshut.authorization import require_claim

  @require_claim("exp", lambda exp: datetime.now(timezone.utc).timestamp() < exp)
  def on_get(self, req, resp): ...
  ```

### Stacking decorators with the same claim name

The internal storage for claim rules is a list of `(claim_name, claim_check)` tuples. Stacking multiple decorators with the same `claim_name` but different `check` values is supported and cumulative:

```python
@allow_claim("scope", "read")
@allow_claim("scope", "write")
def on_get(self, req, resp):
    # At least one must match (OR semantics) — "read" OR "write"
    ...
```

The same applies to `@deny_claim` and `@require_claim`:

```python
@deny_claim("scope", "admin-only")
@deny_claim("scope", "readonly")
def on_patch(self, req, resp):
    # Any match blocks (DENY semantics) — blocks if scope is "admin-only" OR "readonly"
    ...
```

For `@require_claim`, each decorator adds to the AND set — all listed claims must match:

```python
@require_claim("role", "admin")
@require_claim("scope", "write")
def on_delete(self, req, resp):
    # Both must match (AND semantics)
    ...
```

### Type signatures

All three claim decorators share this signature shape:

```python
def allow_claim(claim_name: str, claim_check: ClaimEvaluator | Any | None = None, *, is_required: bool = False) -> Callable[[DecoratedT], DecoratedT]: ...

def deny_claim(claim_name: str, claim_check: ClaimEvaluator | Any | None = None) -> Callable[[DecoratedT], DecoratedT]: ...

def require_claim(claim_name: str, claim_check: ClaimEvaluator | Any | None = None) -> Callable[[DecoratedT], DecoratedT]: ...
```

`claim_name` is always the first (and only required) positional argument. `claim_check` is the second positional argument and may be `None`, a literal value, or a `ClaimEvaluator` callable. Setting `is_required=True` on `allow_claim` upgrades it to REQUIRED logic (equivalent to `require_claim`).

### Evaluation order

When claim rules coexist on a handler, they are evaluated in this order:

1. **DENY** first → immediate block on any match
2. **REQUIRED** next → block if any required claim missing/mismatch
3. **ALLOW** last → block unless at least one matches
4. No ALLOW rules defined → valid token passes through

---

## 2. Middleware

Two middleware classes intercept requests before handler execution. Install on the Falcon app:

```python
import falcon
from reshut.middleware import ASGIAuthorizationMiddleware, WSGIAuthorizationMiddleware

# ASGI app
app = falcon.App(middleware=[ASGIAuthorizationMiddleware(jwk=my_key)])

# WSGI app
app = falcon.App(middleware=[WSGIAuthorizationMiddleware(jwk=my_key)])
```

### Constructor parameters

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `jwk` | `JWK` | *(required)* | The JWK to validate tokens |
| `algorithm` | `Algorithm` | Auto-detected from JWK | Signing algorithm |
| `enforce` | `bool` | `True` | Enforce `exp` and `nbf` claims |
| `audience` | `Optional[str]` | `None` | Expected `aud` claim |
| `issuer` | `Optional[str]` | `None` | Expected `iss` claim |
| `subject` | `Optional[str]` | `None` | Expected `sub` claim |
| `revocation_evaluator` | `Optional[Any]` | `None` | Callable returning revoked token IDs |

### Auth schemes

The middleware checks these headers in order:

1. `Authorization: Bearer <token>` (default)
2. `Authorization: Basic <token>`
3. `X-API-Key: <token>`

### Flow

```
Request → Middleware.process_resource
    → Check __reshut_noauth → skip auth if True
    → Check revocation evaluator
    → Extract token from auth headers
    → Resolve handler claim rules (__reshut_deny, __reshut_allow, __reshut_require)
    → Dispatch to TokenEvaluator
    → Validate JWT → Evaluate claims → Allow or falcon.HTTPUnauthorized
```

---

## 3. Algorithm Support

11 cryptographic algorithms via the `Algorithm` StrEnum (also usable as plain strings):

| Algorithm | Type | Key | Performance (higher → faster) |
|-----------|------|-----|-------------|
| `HS256` | HMAC + SHA-256 | Symmetric (secret) | 9 |
| `HS384` | HMAC + SHA-384 | Symmetric (secret) | 8 |
| `HS512` | HMAC + SHA-512 | Symmetric (secret) | 7 |
| `ED25519` | EdDSA (Edwards25519) | Asymmetric (public/private) | 6 |
| `ED448` | EdDSA (Edwards448) | Asymmetric (public/private) | 5 |
| `ES256` | ECDSA + SHA-256 (P-256) | Asymmetric (public/private) | 4 |
| `ES384` | ECDSA + SHA-384 (P-384) | Asymmetric (public/private) | 3 |
| `ES512` | ECDSA + SHA-512 (P-521) | Asymmetric (public/private) | 2 |
| `RS256` | RSA + SHA-256 | Asymmetric (public/private) | 1 |
| `RS384` | RSA + SHA-384 | Asymmetric (public/private) | 1 |
| `RS512` | RSA + SHA-512 | Asymmetric (public/private) | 1 |

---

## 4. JWK Support

JWK (JSON Web Key) types are defined as TypedDicts with Literal discrimination:

```python
from reshut.jwk import RSAJWK, ECJWK, OKPJWK, OctetJWK, JWK, JWKKeyType

# Discriminate by kty
match jwk:
    case {"kty": "RSA"} as rsa: ...  # RSAJWK
    case {"kty": "EC"} as ec: ...    # ECJWK
    case {"kty": "OKP"} as okp: ...  # OKPJWK
    case {"kty": "oct"} as octj: ... # OctetJWK
```

### Key field types

| Type | `kty` | Fields |
|------|-------|--------|
| `RSAJWK` | `"RSA"` | `kty, kid?, use?, alg?, n, e, d, p, q, dp, dq, qi?` |
| `ECJWK` | `"EC"` | `kty, kid?, use?, alg?, crv, x, y, d?` |
| `OKPJWK` | `"OKP"` | `kty, kid?, use?, alg?, crv, x, d?` |
| `OctetJWK` | `"oct"` | `kty, kid?, use?, alg?, k` |

### Key conversion utilities (in `reshut.jwk.utils`)

| Function | Purpose |
|----------|---------|
| `from_private_key(algorithm, key, *, usage, key_id)` | cryptography private key → JWK |
| `to_private_key(jwk)` | JWK → cryptography private key |
| `from_public_key(algorithm, key, *, usage, key_id)` | cryptography public key → JWK |
| `to_public_key(jwk)` | JWK → cryptography public key |
| `from_symmetric_key_bytes(algorithm, key, *, usage, key_id)` | bytes/string → OctetJWK |
| `to_symmetric_key_bytes(jwk)` | OctetJWK → raw bytes |

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from reshut.jwk.utils import from_private_key, to_public_key, Algorithm

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = from_private_key(Algorithm.RS256, private_key)  # JWK dict

public_key = to_public_key(jwk)  # cryptography RSAPublicKey
```

---

## 5. JWT Utilities

High-level token operations in `reshut.utils`:

### `keygen(algorithm, *, key_size: Optional[int] = None) -> JWK`

Generates a new JWK for the given algorithm.

```python
from reshut.utils import keygen
from reshut import Algorithm

# Symmetric
secret_jwk = keygen(Algorithm.HS256)

# Asymmetric
rsa_jwk = keygen(Algorithm.RS256)
ec_jwk = keygen(Algorithm.ES256)
ed_jwk = keygen(Algorithm.ED25519)
```

For RSA/ECDSA, pass `key_size` to control key length.

### `tokenize(key: JWK, claims: dict, *, ..., algorithm: Optional[str] = None, headers: Optional[dict] = None) -> str`

Creates a signed JWT. Standard claims are injected automatically:

| Param | Type | Default | JWT claim |
|-------|------|---------|-----------|
| `audience` | `Optional[str | list[str]]` | `None` | `aud` |
| `issuer` | `Optional[str]` | `None` | `iss` |
| `subject` | `Optional[str]` | `None` | `sub` |
| `expiry` | `Optional[int]` | `None` | `exp` (unix timestamp) |
| `not_before` | `Optional[int]` | `None` | `nbf` (unix timestamp) |
| `issued_at` | `Optional[int]` | `None` | `iat` (auto-filled if absent) |
| `token_id` | `Optional[str]` | `None` | `jti` |

```python
jwt_token = tokenize(
    key=private_jwk,
    claims={"user_id": 42, "role": "admin"},
    audience="my-api",
    issuer="auth-server",
    expiry=1699999999,  # unix timestamp
)
```

### `validate(key: JWK, token: str, *, enforce: bool = True, audience: Optional[str] = None, issuer: Optional[str] = None, subject: Optional[str] = None) -> dict[str, Any]`

Decodes, verifies, and returns the claims dict.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `enforce` | `bool` | `True` | Enforce `exp` and `nbf` claims |
| `audience` | `Optional[str]` | `None` | Expected `aud` claim |
| `issuer` | `Optional[str]` | `None` | Expected `iss` claim |
| `subject` | `Optional[str]` | `None` | Expected `sub` claim |

```python
try:
    claims = validate(public_jwk, token, audience="my-api")
    print(claims["user_id"])  # 42
except Exception:
    print("token invalid or claims mismatch")
```

`validate` raises plain `Exception` with human-readable error messages (e.g., `'token has expired (exp check failed)'`, `'audience is incorrect.'`). It does not raise `pyjwt.InvalidTokenError` or `cryptography.exceptions.InvalidSignature`.

---

## 6. CLI Tools

The CLI is invoked via `python -m reshut` with subcommands. Note: `claim_check` values for decorators must be passable to `str()` — all `int` values work. `list` values (e.g. for `aud`) require using `@allow_claim` with a raw (unquoted) JSON value, as the CLI does not support JSON value escaping:
```bash
reshut-tokenize secret.jwk --claims '{"aud": 12345}'
```
```python
@allow_claim("aud", lambda c: str(c) == "12345")
```
Wrapper scripts `reshut-keygen`, `reshut-tokenize`, `reshut-validate` are installed as data-files under `bin/`.

### `reshut keygen`

Generate a JWK and write to a `.jwk` file.

```bash
python -m reshut keygen --type HS256 --output secret
# Writes: secret.jwk

python -m reshut keygen --type ES256 --output ec
# Writes: ec.jwk

python -m reshut keygen --type ED25519 --output eddsa
# Writes: eddsa.jwk
```

Arguments:
| Flag | Description |
|------|-------------|
| `--type` | Algorithm name (e.g. `HS256`, `RS256`) — required |
| `--output` | Base filename (prefix) for generated key files — required |

### `reshut tokenize`

Create a JWT from claims + key file.

```bash
python -m reshut tokenize --key secret.jwk --claims '{"user_id": 42, "role": "admin"}'
```

Arguments:
| Flag | Description |
|------|-------------|
| `--key` | Path to the JWK key file — required |
| `--claims` | JSON string representing the claim set (must be a JSON object) — required |

### `reshut validate`

Validate a token and print decoded claims.

```bash
python -m reshut validate --key secret.jwk --token <token_string>
```

Arguments:
| Flag | Description |
|------|-------------|
| `--key` | Path to the JWK key file — required |
| `--token` | JWT string to validate — required |

Returns: JSON-encoded claims (sorted, indented) on success, or an error message on stderr on failure. Non-zero exit codes: 2 (unsupported algorithm), 3 (key file read error), 5 (invalid claims JSON), 7 (token validation failed).

---

## 7. Usage Patterns

### Basic Falcon app with middleware

```python
import falcon
from reshut.middleware import ASGIAuthorizationMiddleware, TokenEvaluator
from reshut.authorization import require_claim, allow_anonymous
from reshut.utils import keygen
from reshut import Algorithm

key = keygen(Algorithm.ES256)
token_evaluator = TokenEvaluator(key)

class PublicResource:
    @allow_anonymous
    def on_get(self, req, resp):
        resp.media = {"message": "hello"}

class AdminResource:
    @require_claim("role", "admin")
    def on_get(self, req, resp):
        resp.media = {"data": "secret"}

app = falcon.App(
    middleware=[ASGIAuthorizationMiddleware(bearer_token_evaluator=token_evaluator)]
)
app.add_route("/public", PublicResource())
app.add_route("/admin", AdminResource())
```

### Token revocation

```python
from reshut.middleware import ASGIAuthorizationMiddleware, TokenEvaluator

# A revocation evaluator re-validates the token (which may contain
# a revocation flag or jti). Any TokenEvaluator can serve as the
# revocation check since it always validates the token's signature.
middleware = ASGIAuthorizationMiddleware(
    bearer_token_evaluator=TokenEvaluator(key),
    revokation_evaluator=TokenEvaluator(key)  # note: "revokation"
)
```

### Custom claim evaluator

```python
from datetime import datetime, timezone
from reshut.authorization import deny_claim

@deny_claim("expires_at", lambda v: datetime.now(timezone.utc).timestamp() > v)
def on_get(self, req, resp):
    resp.media = {"status": "ok"}
```

---

## 8. Package Map

Top-level package layout:

```
src/reshut/
├── __init__.py          # Algorithm, submodules, __version__, __commit__
├── __main__.py          # CLI entry point (python -m reshut)
├── algorithm.py         # Algorithm StrEnum (11 algorithms)
├── py.typed             # PEP 561 marker
├── utils.py             # keygen, tokenize, validate
├── authorization/
│   ├── __init__.py      # Re-exports decorators and ClaimEvaluator
│   ├── claim_evaluator.py  # ClaimEvaluator type alias
│   └── decorators.py       # allow_anonymous, allow_claim, deny_claim, require_claim
├── jwk/
│   ├── __init__.py      # Re-exports JWK types and utils
│   ├── jwk.py               # JWK union type
│   ├── _jwk.py              # _JWK base TypedDict (kid, use, alg)
│   ├── rsa_jwk.py         # RSAJWK TypedDict
│   ├── ec_jwk.py          # ECJWK TypedDict
│   ├── okp_jwk.py         # OKPJWK TypedDict
│   ├── octet_jwk.py       # OctetJWK TypedDict
│   ├── jwk_key_type.py    # JWKKeyType StrEnum (RSA, EC, OKP, OCT)
│   ├── jwk_curve_type.py  # JWKCurveType StrEnum (P256, P384, P521, ED25519, ED448)
│   ├── jwk_usage_type.py  # JWKUsageType StrEnum (SIG, ENC)
│   └── utils.py           # Key conversion functions
└── middleware/
    ├── __init__.py      # Re-exports all middleware classes
    ├── asgi_authorization_middleware.py  # ASGI middleware
    ├── authorization_evaluator.py        # Request → TokenEvaluator bridge
    ├── token_evaluator.py               # Single-token validation & claims
    └── wsgi_authorization_middleware.py # WSGI middleware
```

### Module exports map

| Module | Exports |
|--------|---------|
| `reshut.__init__` | `__version__`, `__commit__`, `Algorithm`, submodules: `authorization`, `jwk`, `middleware`, `utils` |
| `reshut.algorithm` | `Algorithm` (StrEnum, 11 members) |
| `reshut.authorization` | `ClaimEvaluator`, `allow_anonymous`, `allow_claim`, `deny_claim`, `require_claim` |
| `reshut.jwk` | `JWKUsageType`, `JWKKeyType`, `JWKCurveType`, `RSAJWK`, `ECJWK`, `OKPJWK`, `OctetJWK`, `JWK`, `utils` |
| `reshut.jwk.utils` | `from_private_key`, `to_private_key`, `from_public_key`, `to_public_key`, `from_symmetric_key_bytes`, `to_symmetric_key_bytes` |
| `reshut.utils` | `keygen`, `tokenize`, `validate` |
| `reshut.middleware` | `ASGIAuthorizationMiddleware`, `AuthorizationEvaluator`, `TokenEvaluator`, `WSGIAuthorizationMiddleware` |
| `reshut.middleware.ASGIAuthorizationMiddleware` | `ASGIAuthorizationMiddleware` |
| `reshut.middleware.AuthorizationEvaluator` | `AuthorizationEvaluator` |
| `reshut.middleware.TokenEvaluator` | `TokenEvaluator` |
| `reshut.middleware.WSGIAuthorizationMiddleware` | `WSGIAuthorizationMiddleware` |

### Dependency graph

```
algorithm.py (stdlib only)
    ^
jwk/_jwk.py -> algorithm, jwk_usage_type
jwk/*_jwk.py -> _jwk + specific types (jwk_key_type, jwk_curve_type)
jwk/utils.py -> algorithm, jwk types, cryptography
jwk/__init__.py -> all JWK types + utils
    ^
utils.py -> algorithm, jwk, pyjwt, cryptography
    ^
authorization/claim_evaluator.py (stdlib only)
authorization/decorators.py -> claim_evaluator
    ^
middleware/token_evaluator.py -> authorization, jwk, utils, falcon
    ^
middleware/authorization_evaluator.py -> token_evaluator, falcon
    ^
middleware/asgi_authorization_middleware.py -> authorization_evaluator, token_evaluator, falcon
middleware/wsgi_authorization_middleware.py -> authorization_evaluator, token_evaluator, falcon
```

### Import layers

| Layer | Modules | Role |
|-------|---------|------|
| 1 | `algorithm` | Foundation — bare StrEnum, no external deps |
| 2 | `jwk/*` | Key representation — depends on Layer 1 |
| 3 | `utils`, `authorization` | Core operations — token CRUD + decorator metadata |
| 4 | `middleware/*` | Falcon integration — ties requests to handler claims |


| Import from `reshut` | Purpose |
|----------------------|---------|
| `Algorithm` | StrEnum of 11 crypto algorithms |
| `authorization.allow_anonymous` | Bypass auth decorator |
| `authorization.allow_claim` | Allow if any claim matches |
| `authorization.deny_claim` | Deny if any claim matches |
| `authorization.require_claim` | Require all claims to match |
| `authorization.ClaimEvaluator` | Type alias `Callable[[Any], bool]` |
| `jwk.RSAJWK, ECJWK, OKPJWK, OctetJWK` | JWK TypedDict types |
| `jwk.JWK` | Union of all JWK types |
| `jwk.utils.from_private_key()` | Key object → JWK |
| `jwk.utils.to_public_key()` | JWK → key object |
| `utils.keygen()` | Generate new JWK |
| `utils.tokenize()` | Sign JWT |
| `utils.validate()` | Decode & verify JWT |
| `middleware.ASGIAuthorizationMiddleware` | ASGI middleware |
| `middleware.WSGIAuthorizationMiddleware` | WSGI middleware |
| `middleware.TokenEvaluator` | Core token + claim evaluation |
| `middleware.AuthorizationEvaluator` | Request → claim rule bridge |

### CLI binaries

| Binary | Purpose |
|--------|---------|
| `reshut keygen` | Generate JWK file |
| `reshut tokenize` | Create signed JWT |
| `reshut validate` | Decode & verify JWT |
