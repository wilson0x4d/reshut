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

def require_claim(claim_name: str, claim_check: Any) -> Callable[[DecoratedT], DecoratedT]: ...
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
from reshut.middleware import AsgiAuthorizationMiddleware, WsgiAuthorizationMiddleware

# ASGI app
app = falcon.App(middleware=[AsgiAuthorizationMiddleware(jwk=my_key)])

# WSGI app
app = falcon.App(middleware=[WsgiAuthorizationMiddleware(jwk=my_key)])
```

### Constructor parameters

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `jwk` | `Jwk` | *(required)* | The JWK to validate tokens |
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

| Algorithm | Type | Key | Performance |
|-----------|------|-----|-------------|
| `HS256` | HMAC + SHA-256 | Symmetric (secret) | Fast |
| `HS384` | HMAC + SHA-384 | Symmetric (secret) | Fast |
| `HS512` | HMAC + SHA-512 | Symmetric (secret) | Fast |
| `RS256` | RSA + SHA-256 | Asymmetric (public/private) | Medium |
| `RS384` | RSA + SHA-384 | Asymmetric (public/private) | Medium |
| `RS512` | RSA + SHA-512 | Asymmetric (public/private) | Medium |
| `ES256` | ECDSA + SHA-256 (P-256) | Asymmetric (public/private) | Medium |
| `ES384` | ECDSA + SHA-384 (P-384) | Asymmetric (public/private) | Slower |
| `ES512` | ECDSA + SHA-512 (P-521) | Asymmetric (public/private) | Slower |
| `ED25519` | EdDSA (Edwards25519) | Asymmetric (public/private) | Fast |
| `ED448` | EdDSA (Edwards448) | Asymmetric (public/private) | Medium |

---

## 4. JWK Support

JWK (JSON Web Key) types are defined as TypedDicts with Literal discrimination:

```python
from reshut.jwk import RsaJwk, EcJwk, OkpJwk, OctetJwk, Jwk, JwkKeyType

# Discriminate by kty
match jwk:
    case {"kty": "RSA"} as rsa: ...  # RsaJwk
    case {"kty": "EC"} as ec: ...    # EcJwk
    case {"kty": "OKP"} as okp: ...  # OkpJwk
    case {"kty": "oct"} as octj: ... # OctetJwk
```

### Key field types

| Type | `kty` | Fields |
|------|-------|--------|
| `RsaJwk` | `"RSA"` | `kty, kid?, use?, alg?, n, e, d, p, q, dp, dq, qi?` |
| `EcJwk` | `"EC"` | `kty, kid?, use?, alg?, crv, x, y, d?` |
| `OkpJwk` | `"OKP"` | `kty, kid?, use?, alg?, crv, x, d?` |
| `OctetJwk` | `"oct"` | `kty, kid?, use?, alg?, k` |

### Key conversion utilities

| Function | Purpose |
|----------|---------|
| `from_private_key(algorithm, key)` | cryptography private key → JWK |
| `to_private_key(jwk)` | JWK → cryptography private key |
| `from_public_key(algorithm, key)` | cryptography public key → JWK |
| `to_public_key(jwk)` | JWK → cryptography public key |
| `from_symmetric_key(algorithm, key)` | bytes/string → OctetJwk |
| `to_symmetric_key(jwk)` | OctetJwk → raw bytes |

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from reshut.jwk import from_private_key, to_public_key, Algorithm

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = from_private_key(Algorithm.RS256, private_key)  # JWK dict

public_key = to_public_key(jwk)  # cryptography RSAPublicKey
```

---

## 5. JWT Utilities

High-level token operations in `reshut.utils`:

### `keygen(algorithm, *, key_size: Optional[int] = None) -> Jwk`

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

### `tokenize(key: Jwk, claims: dict, *, ..., algorithm: Optional[str] = None, headers: Optional[dict] = None) -> str`

Creates a signed JWT. Standard claims are injected automatically:

| Param | Type | Default | JWT claim |
|-------|------|---------|-----------|
| `audience` | `Optional[str]` | `None` | `aud` |
| `issuer` | `Optional[str]` | `None` | `iss` |
| `subject` | `Optional[str]` | `None` | `sub` |
| `expiry` | `Optional[float \| timedelta]` | `None` | `exp` |
| `not_before` | `Optional[float \| timedelta]` | `None` | `nbf` |
| `issued_at` | `Optional[float]` | `None` | `iat` |
| `token_id` | `Optional[str]` | `None` | `jti` |

```python
jwt_token = tokenize(
    key=private_jwk,
    claims={"user_id": 42, "role": "admin"},
    audience="my-api",
    issuer="auth-server",
    expiry=600,  # seconds
)
```

### `validate(key: Jwk, token: str, *, ..., algorithm: Optional[str] = None, enforce: Optional[bool] = None) -> dict`

Decodes, verifies, and returns the claims dict.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `enforce` | `Optional[bool]` | `True` | Enforce `exp` and `nbf` claims |
| `audience` | `Optional[str]` | `None` | Expected `aud` claim |
| `issuer` | `Optional[str]` | `None` | Expected `iss` claim |
| `subject` | `Optional[str]` | `None` | Expected `sub` claim |

```python
from cryptography.exceptions import InvalidSignature
import jwt as pyjwt

try:
    claims = validate(public_jwk, token, audience="my-api")
    print(claims["user_id"])  # 42
except pyjwt.InvalidTokenError:
    print("token expired")
except InvalidSignature:
    print("invalid signature")
```

---

## 6. CLI Tools

Three binaries installed with reshut:

### `reshut-keygen`

Generate a private key and write to a `.jwk` file.

```bash
# Symmetric key
reshut-keygen HS256 -o secret.jwk

# RSA key
reshut-keygen RS256 -o rsa.jwk

# EC key
reshut-keygen ES256 -o ec.jwk

# EdDSA key
reshut-keygen ED25519 -o eddsa.jwk
```

Options: `-o` / `--output` output file, `-a` / `--algorithm` (default from key type), `--key-size` for RSA/ECDSA.

### `reshut-tokenize`

Create a JWT from claims + key file.

```bash
reshut-tokenize secret.jwk --claim user_id=42 --claim role=admin --aud my-api
```

Options:
| Flag | Description |
|------|-------------|
| `--claim` | Claim in `key=value` format (repeatable) |
| `--aud` | `aud` (audience) |
| `--iss` | `iss` (issuer) |
| `--sub` | `sub` (subject) |
| `--exp` | Expiry in seconds from now |
| `--nbf` | Not-before in seconds from now |
| `-a` | Algorithm override |
| `--alg` | Same as `-a` |

### `reshut-validate`

Validate a token and print decoded claims.

```bash
reshut-validate secret.jwk <token_string> --aud my-api
```

Options:
| Flag | Description |
|------|-------------|
| `--aud` | Expected audience |
| `--iss` | Expected issuer |
| `--sub` | Expected subject |
| `-a` / `--alg` | Algorithm |
| `--no-enforce` | Skip exp/nbf enforcement |

---

## 7. Usage Patterns

### Basic Falcon app with middleware

```python
import falcon
from reshut.middleware import AsgiAuthorizationMiddleware
from reshut.authorization import require_claim, allow_anonymous
from reshut.utils import keygen

key = keygen("HS256")

class PublicResource:
    @allow_anonymous
    def on_get(self, req, resp):
        resp.media = {"message": "hello"}

class AdminResource:
    @require_claim("role", "admin")
    def on_get(self, req, resp):
        resp.media = {"data": "secret"}

app = falcon.App(
    middleware=[AsgiAuthorizationMiddleware(jwk=key)]
)
app.add_route("/public", PublicResource())
app.add_route("/admin", AdminResource())
```

### Token revocation

```python
from reshut.middleware import AsgiAuthorizationMiddleware

revoked_tokens = {"token_123", "token_456"}

def revocation_evaluator(token_id: str | None) -> bool:
    return token_id in revoked_tokens

middleware = AsgiAuthorizationMiddleware(
    jwk=key,
    revocation_evaluator=revocation_evaluator
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
├── Algorithm.py         # Algorithm StrEnum (11 algorithms)
├── authorization.py     # Decorator functions
├── jwk.py               # JWK TypedDicts, enums, conversion functions
├── utils.py             # keygen, tokenize, validate
└── middleware/
    ├── __init__.py      # Re-exports all middleware classes
    ├── AsgiAuthorizationMiddleware.py  # ASGI middleware
    ├── AuthorizationEvaluator.py       # Request → TokenEvaluator bridge
    ├── TokenEvaluator.py               # Single-token validation & claims
    └── WsgiAuthorizationMiddleware.py # WSGI middleware
```

### Module exports map

| Module | Exports |
|--------|---------|
| `reshut.__init__` | `__version__`, `__commit__`, `Algorithm`, submodules: `authorization`, `jwk`, `middleware`, `utils` |
| `reshut.Algorithm` | `Algorithm` (StrEnum, 11 members) |
| `reshut.authorization` | `ClaimEvaluator`, `allow_anonymous`, `allow_claim`, `deny_claim`, `require_claim` |
| `reshut.jwk` | `JwkUsageType`, `JwkKeyType`, `JwkCurveType`, `RsaJwk`, `EcJwk`, `OkpJwk`, `OctetJwk`, `Jwk`, `from_private_key`, `to_private_key`, `from_public_key`, `to_public_key`, `from_symmetric_key`, `to_symmetric_key` |
| `reshut.utils` | `keygen`, `tokenize`, `validate` |
| `reshut.middleware` | `AsgiAuthorizationMiddleware`, `AuthorizationEvaluator`, `TokenEvaluator`, `WsgiAuthorizationMiddleware` |
| `reshut.middleware.AsgiAuthorizationMiddleware` | `AsgiAuthorizationMiddleware` |
| `reshut.middleware.AuthorizationEvaluator` | `AuthorizationEvaluator` |
| `reshut.middleware.TokenEvaluator` | `TokenEvaluator` |
| `reshut.middleware.WsgiAuthorizationMiddleware` | `WsgiAuthorizationMiddleware` |

### Dependency graph

```
Algorithm.py (stdlib only)
    ↑
jwk.py → Algorithm, cryptography
    ↑
utils.py → Algorithm, jwk, jwt, cryptography
    ↑
authorization.py (stdlib only)
    ↑
middleware/TokenEvaluator.py → authorization, jwk, utils, falcon
    ↑
middleware/AuthorizationEvaluator.py → authorization, TokenEvaluator, falcon
    ↑
middleware/AsgiAuthorizationMiddleware.py → AuthorizationEvaluator, TokenEvaluator, falcon
middleware/WsgiAuthorizationMiddleware.py → AuthorizationEvaluator, TokenEvaluator, falcon
```

### Import layers

| Layer | Modules | Role |
|-------|---------|------|
| 1 | `Algorithm` | Foundation — bare StrEnum, no external deps |
| 2 | `jwk` | Key representation — depends on Layer 1 |
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
| `jwk.RsaJwk, EcJwk, OkpJwk, OctetJwk` | JWK TypedDict types |
| `jwk.Jwk` | Union of all JWK types |
| `jwk.from_private_key()` | Key object → JWK |
| `jwk.to_public_key()` | JWK → key object |
| `utils.keygen()` | Generate new JWK |
| `utils.tokenize()` | Sign JWT |
| `utils.validate()` | Decode & verify JWT |
| `middleware.AsgiAuthorizationMiddleware` | ASGI middleware |
| `middleware.WsgiAuthorizationMiddleware` | WSGI middleware |
| `middleware.TokenEvaluator` | Core token + claim evaluation |
| `middleware.AuthorizationEvaluator` | Request → claim rule bridge |

### CLI binaries

| Binary | Purpose |
|--------|---------|
| `reshut-keygen` | Generate JWK file |
| `reshut-tokenize` | Create signed JWT |
| `reshut-validate` | Decode & verify JWT |
