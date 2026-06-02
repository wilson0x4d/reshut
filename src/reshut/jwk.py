# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from enum import StrEnum, unique
from typing import Literal, Optional, TypedDict, Union, cast
from .Algorithm import Algorithm


@unique
class JwkUsageType(StrEnum):
    """
    JWK Use
    """
    SIG = 'sig'
    ENC = 'enc'


@unique
class JwkKeyType(StrEnum):
    """
    JWK Key Type
    """
    RSA = 'RSA'
    EC = 'EC'
    OKP = 'OKP'
    OCT = 'oct'


@unique
class JwkCurveType(StrEnum):
    P256 = 'P-256'
    P384 = 'P-384'
    P521 = 'P-521'
    ED25519 = 'Ed25519'
    ED448 = 'Ed448'


class _Jwk(TypedDict, total=False):
    kid: str
    use: JwkUsageType
    alg: Algorithm


class RsaJwk(_Jwk, total=False):
    kty: Literal[JwkKeyType.RSA]
    n: str
    e: str
    # prikey fields
    d: str
    p: str
    q: str
    dp: str
    dq: str
    qi: str


class EcJwk(_Jwk, total=False):
    kty: Literal[JwkKeyType.EC]
    crv: Literal[JwkCurveType.P256, JwkCurveType.P384, JwkCurveType.P521]
    x: str
    y: str
    # prikey fields
    d: str


class OkpJwk(_Jwk, total=False):
    kty: Literal[JwkKeyType.OKP]
    crv: Literal[JwkCurveType.ED25519, JwkCurveType.ED448]
    x: str
    # prikey fields
    d: str


class OctetJwk(_Jwk, total=False):
    kty: Literal[JwkKeyType.OCT]
    k: str


Jwk = Union[RsaJwk, EcJwk, OkpJwk, OctetJwk]


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
    usage: JwkUsageType = JwkUsageType.SIG,
    key_id: Optional[str] = None
) -> Jwk:
    result: Jwk
    if isinstance(key, ed448.Ed448PrivateKey):
        ed448_priv = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed448_pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OkpJwk(
            kty=JwkKeyType.OKP,
            crv=JwkCurveType.ED448,
            x=__b64_from_bytes(ed448_pub),
            d=__b64_from_bytes(ed448_priv),
            alg=algorithm,
            use=usage
        )
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        ed25519_priv = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed25519_pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OkpJwk(
            kty=JwkKeyType.OKP,
            crv=JwkCurveType.ED25519,
            x=__b64_from_bytes(ed25519_pub),
            d=__b64_from_bytes(ed25519_priv),
            alg=algorithm,
            use=usage
        )
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        ec_public = key.private_numbers().public_numbers
        ec_private = key.private_numbers().private_value
        result = EcJwk(
            kty=JwkKeyType.EC,
            crv=JwkCurveType.P256 if key.curve.name == 'secp256r1' else JwkCurveType.P384 if key.curve.name == 'secp384r1' else JwkCurveType.P521,
            x=__b64_from_int(ec_public.x),
            y=__b64_from_int(ec_public.y),
            d=__b64_from_int(ec_private),
            alg=algorithm,
            use=usage
        )
    elif isinstance(key, rsa.RSAPrivateKey):
        rsa_priv = key.private_numbers()
        rsa_pub = rsa_priv.public_numbers
        result = RsaJwk(
            kty=JwkKeyType.RSA,
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


def to_private_key(jwk: Jwk) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey:
    match JwkKeyType(jwk['kty']):
        case JwkKeyType.RSA:
            rsa_jwk = cast(RsaJwk, jwk)
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
        case JwkKeyType.EC:
            ec_jwk = cast(EcJwk, jwk)
            curve = {
                JwkCurveType.P256: ec.SECP256R1(),
                JwkCurveType.P384: ec.SECP384R1(),
                JwkCurveType.P521: ec.SECP521R1(),
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
        case JwkKeyType.OKP:
            okp_jwk = cast(OkpJwk, jwk)
            raw = __b64_to_bytes(okp_jwk['d'])
            match JwkCurveType(okp_jwk['crv']):
                case JwkCurveType.ED25519:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
                case JwkCurveType.ED448:
                    return ed448.Ed448PrivateKey.from_private_bytes(raw)
                case _:
                    raise ValueError('Unsupported OKP Curve')
        case _:
            raise ValueError('Unsupported JWK')


def from_public_key(
    algorithm: Algorithm,
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
    usage: JwkUsageType = JwkUsageType.SIG,
    key_id: Optional[str] = None
) -> Jwk:
    result: Jwk
    if isinstance(key, ed448.Ed448PublicKey):
        ed448_pub = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OkpJwk(
            kty=JwkKeyType.OKP,
            crv=JwkCurveType.ED448,
            x=__b64_from_bytes(ed448_pub),
            alg=algorithm,
            use=usage,
        )
    elif isinstance(key, ed25519.Ed25519PublicKey):
        ed25519_pub = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        result = OkpJwk(
            kty=JwkKeyType.OKP,
            crv=JwkCurveType.ED25519,
            x=__b64_from_bytes(ed25519_pub),
            alg=algorithm,
            use=usage,
        )
    elif isinstance(key, ec.EllipticCurvePublicKey):
        ec_pub = key.public_numbers()
        result = EcJwk(
            kty=JwkKeyType.EC,
            crv=JwkCurveType.P256 if key.curve.name == 'secp256r1' else JwkCurveType.P384 if key.curve.name == 'secp384r1' else JwkCurveType.P521,
            x=__b64_from_int(ec_pub.x),
            y=__b64_from_int(ec_pub.y),
            alg=algorithm,
            use=usage,
        )
    elif isinstance(key, rsa.RSAPublicKey):
        rsa_pub = key.public_numbers()
        result = RsaJwk(
            kty=JwkKeyType.RSA,
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


def to_public_key(jwk: Jwk) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey:
    match JwkKeyType(jwk['kty']):
        case JwkKeyType.RSA:
            rsa_jwk = cast(RsaJwk, jwk)
            rsa_pub = rsa.RSAPublicNumbers(
                e=__b64_to_int(rsa_jwk['e']),
                n=__b64_to_int(rsa_jwk['n'])
            )
            return rsa_pub.public_key()
        case JwkKeyType.EC:
            ec_jwk = cast(EcJwk, jwk)
            curve = {
                JwkCurveType.P256: ec.SECP256R1(),
                JwkCurveType.P384: ec.SECP384R1(),
                JwkCurveType.P521: ec.SECP521R1(),
            }[ec_jwk['crv']]
            ec_pub = ec.EllipticCurvePublicNumbers(
                x=__b64_to_int(ec_jwk['x']),
                y=__b64_to_int(ec_jwk['y']),
                curve=curve
            )
            return ec_pub.public_key()
        case JwkKeyType.OKP:
            okp_jwk = cast(OkpJwk, jwk)
            key_bytes = __b64_to_bytes(okp_jwk['x'])
            match JwkCurveType(okp_jwk['crv']):
                case JwkCurveType.ED25519:
                    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
                case JwkCurveType.ED448:
                    return ed448.Ed448PublicKey.from_public_bytes(key_bytes)
                case _:
                    raise ValueError('Unsupported OKP Curve Type')
        case _:
            raise ValueError('Unsupported JWK')


def from_symmetric_key(
    algorithm: Algorithm,
    key: bytes | str,
    usage: JwkUsageType = JwkUsageType.SIG,
    key_id: Optional[str] = None
) -> OctetJwk:
    if isinstance(key, str):
        key = key.encode('utf-8')
    result = OctetJwk(
        kty=JwkKeyType.OCT,
        k=__b64_from_bytes(key),
        alg=algorithm,
        use=usage
    )
    if key_id is not None:
        result['kid'] = key_id
    return result


def to_symmetric_key(jwk: OctetJwk) -> bytes:
    if jwk['kty'] != JwkKeyType.OCT:
        raise ValueError('Unsupported Key Type')
    else:
        return __b64_to_bytes(jwk['k'])


__all__ = [
    'JwkUsageType',
    'JwkKeyType',
    'JwkCurveType',
    'RsaJwk',
    'EcJwk',
    'OkpJwk',
    'OctetJwk',
    'Jwk',
    'from_private_key', 'to_private_key',
    'from_public_key', 'to_public_key',
    'from_symmetric_key', 'to_symmetric_key'
]
