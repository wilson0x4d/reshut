# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from typing import Optional, cast

from ..algorithm import Algorithm
from .jwk import JWK
from .jwk_curve_type import JWKCurveType
from .jwk_key_type import JWKKeyType
from .jwk_usage_type import JWKUsageType


def __b64_from_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def __b64_from_int(i: int) -> str:
    return __b64_from_bytes(i.to_bytes((i.bit_length() + 7) // 8, 'big'))


def __b64_to_bytes(b64: str) -> bytes:
    padding = '=' * (-len(b64) % 4)
    return base64.urlsafe_b64decode(b64 + padding)


def __b64_to_int(b64: str) -> int:
    return int.from_bytes(__b64_to_bytes(b64), 'big')


def from_private_key(
    algorithm: Algorithm,
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey,
    usage: JWKUsageType = JWKUsageType.SIG,
    key_id: Optional[str] = None
) -> JWK:
    result: JWK
    if isinstance(key, ed448.Ed448PrivateKey):
        from .okp_jwk import OKPJWK
        ed448_priv = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed448_pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OKPJWK(
            kty=JWKKeyType.OKP,
            crv=JWKCurveType.ED448,
            x=__b64_from_bytes(ed448_pub),
            d=__b64_from_bytes(ed448_priv),
            alg=algorithm,
            use=usage
        )
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        from .okp_jwk import OKPJWK
        ed25519_priv = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed25519_pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OKPJWK(
            kty=JWKKeyType.OKP,
            crv=JWKCurveType.ED25519,
            x=__b64_from_bytes(ed25519_pub),
            d=__b64_from_bytes(ed25519_priv),
            alg=algorithm,
            use=usage
        )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        from .ec_jwk import ECJWK
        ec_public = key.private_numbers().public_numbers
        ec_private = key.private_numbers().private_value
        result = ECJWK(
            kty=JWKKeyType.EC,
            crv=JWKCurveType.P256 if key.curve.name == 'secp256r1' else JWKCurveType.P384 if key.curve.name == 'secp384r1' else JWKCurveType.P521,
            x=__b64_from_int(ec_public.x),
            y=__b64_from_int(ec_public.y),
            d=__b64_from_int(ec_private),
            alg=algorithm,
            use=usage
        )
    elif isinstance(key, rsa.RSAPrivateKey):
        from .rsa_jwk import RSAJWK
        rsa_priv = key.private_numbers()
        rsa_pub = rsa_priv.public_numbers
        result = RSAJWK(
            kty=JWKKeyType.RSA,
            n=__b64_from_int(rsa_pub.n),
            e=__b64_from_int(rsa_pub.e),
            d=__b64_from_int(rsa_priv.d),
            p=__b64_from_int(rsa_priv.p),
            q=__b64_from_int(rsa_priv.q),
            dp=__b64_from_int(rsa_priv.dmp1),
            dq=__b64_from_int(rsa_priv.dmq1),
            qi=__b64_from_int(rsa_priv.iqmp),
            alg=algorithm,
            use=usage
        )
    else:
        raise NotImplementedError('Key not supported.')
    if key_id is not None:
        result['kid']
    return result


def to_private_key(jwk: JWK) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey:
    match JWKKeyType(jwk['kty']):
        case JWKKeyType.RSA:
            from .rsa_jwk import RSAJWK
            rsa_jwk = cast(RSAJWK, jwk)
            rsa_private = rsa.RSAPrivateNumbers(
                p=__b64_to_int(rsa_jwk['p']),
                q=__b64_to_int(rsa_jwk['q']),
                d=__b64_to_int(rsa_jwk['d']),
                dmp1=__b64_to_int(rsa_jwk['dp']),
                dmq1=__b64_to_int(rsa_jwk['dq']),
                iqmp=__b64_to_int(rsa_jwk['qi']),
                public_numbers=rsa.RSAPublicNumbers(
                    e=__b64_to_int(rsa_jwk['e']),
                    n=__b64_to_int(rsa_jwk['n'])
                )
            )
            return rsa_private.private_key()
        case JWKKeyType.EC:
            from .ec_jwk import ECJWK
            ec_jwk = cast(ECJWK, jwk)
            curve = {
                JWKCurveType.P256: ec.SECP256R1(),
                JWKCurveType.P384: ec.SECP384R1(),
                JWKCurveType.P521: ec.SECP521R1(),
            }[ec_jwk['crv']]
            ec_private = ec.EllipticCurvePrivateNumbers(
                private_value=__b64_to_int(ec_jwk['d']),
                public_numbers=ec.EllipticCurvePublicNumbers(
                    x=__b64_to_int(ec_jwk['x']),
                    y=__b64_to_int(ec_jwk['y']),
                    curve=curve
                )
            )
            return ec_private.private_key()
        case JWKKeyType.OKP:
            from .okp_jwk import OKPJWK
            okp_jwk = cast(OKPJWK, jwk)
            raw = __b64_to_bytes(okp_jwk['d'])
            match JWKCurveType(okp_jwk['crv']):
                case JWKCurveType.ED25519:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
                case JWKCurveType.ED448:
                    return ed448.Ed448PrivateKey.from_private_bytes(raw)
                case _:
                    raise ValueError('Unsupported OKP Curve')
        case _:
            raise ValueError('Unsupported JWK')


def from_public_key(
    algorithm: Algorithm,
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
    usage: JWKUsageType = JWKUsageType.SIG,
    key_id: Optional[str] = None
) -> JWK:
    result: JWK
    if isinstance(key, ed448.Ed448PublicKey):
        from .okp_jwk import OKPJWK
        ed448_pub = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OKPJWK(
            kty=JWKKeyType.OKP,
            crv=JWKCurveType.ED448,
            x=__b64_from_bytes(ed448_pub),
            alg=algorithm,
            use=usage,
        )
    elif isinstance(key, ed25519.Ed25519PublicKey):
        from .okp_jwk import OKPJWK
        ed25519_pub = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OKPJWK(
            kty=JWKKeyType.OKP,
            crv=JWKCurveType.ED25519,
            x=__b64_from_bytes(ed25519_pub),
            alg=algorithm,
            use=usage,
        )
    elif isinstance(key, ec.EllipticCurvePublicKey):
        from .ec_jwk import ECJWK
        ec_pub = key.public_numbers()
        result = ECJWK(
            kty=JWKKeyType.EC,
            crv=JWKCurveType.P256 if key.curve.name == 'secp256r1' else JWKCurveType.P384 if key.curve.name == 'secp384r1' else JWKCurveType.P521,
            x=__b64_from_int(ec_pub.x),
            y=__b64_from_int(ec_pub.y),
            alg=algorithm,
            use=usage,
        )
    elif isinstance(key, rsa.RSAPublicKey):
        from .rsa_jwk import RSAJWK
        rsa_pub = key.public_numbers()
        result = RSAJWK(
            kty=JWKKeyType.RSA,
            n=__b64_from_int(rsa_pub.n),
            e=__b64_from_int(rsa_pub.e),
            alg=algorithm,
            use=usage,
        )
    else:
        raise NotImplementedError('Key not supported.')
    if key_id is not None:
        result['kid']
    return result


def to_public_key(jwk: JWK) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey:
    match JWKKeyType(jwk['kty']):
        case JWKKeyType.RSA:
            from .rsa_jwk import RSAJWK
            rsa_jwk = cast(RSAJWK, jwk)
            rsa_pub = rsa.RSAPublicNumbers(
                e=__b64_to_int(rsa_jwk['e']),
                n=__b64_to_int(rsa_jwk['n'])
            )
            return rsa_pub.public_key()
        case JWKKeyType.EC:
            from .ec_jwk import ECJWK
            ec_jwk = cast(ECJWK, jwk)
            curve = {
                JWKCurveType.P256: ec.SECP256R1(),
                JWKCurveType.P384: ec.SECP384R1(),
                JWKCurveType.P521: ec.SECP521R1(),
            }[ec_jwk['crv']]
            ec_pub = ec.EllipticCurvePublicNumbers(
                x=__b64_to_int(ec_jwk['x']),
                y=__b64_to_int(ec_jwk['y']),
                curve=curve
            )
            return ec_pub.public_key()
        case JWKKeyType.OKP:
            from .okp_jwk import OKPJWK
            okp_jwk = cast(OKPJWK, jwk)
            key_bytes = __b64_to_bytes(okp_jwk['x'])
            match JWKCurveType(okp_jwk['crv']):
                case JWKCurveType.ED25519:
                    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                case JWKCurveType.ED448:
                    return ed448.Ed448PublicKey.from_public_bytes(key_bytes)
                case _:
                    raise ValueError('Unsupported OKP Curve Type')
        case _:
            raise ValueError('Unsupported JWK')


def from_symmetric_key(
    algorithm: Algorithm,
    key: bytes | str,
    usage: JWKUsageType = JWKUsageType.SIG,
    key_id: Optional[str] = None
) -> JWK:
    from .octet_jwk import OctetJWK
    if isinstance(key, str):
        key = key.encode('utf-8')
    result = OctetJWK(
        kty=JWKKeyType.OCT,
        k=__b64_from_bytes(key),
        alg=algorithm,
        use=usage
    )
    if key_id is not None:
        result['kid'] = key_id
    return result


def to_symmetric_key(jwk: JWK) -> bytes:
    if jwk['kty'] != JWKKeyType.OCT:
        raise ValueError('Unsupported Key Type')
    else:
        return __b64_to_bytes(jwk['k'])


__all__ = [
    'from_private_key',
    'from_public_key',
    'from_symmetric_key',
    'to_private_key',
    'to_public_key',
    'to_symmetric_key'
]
