# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
import secrets
import jwt
from typing import Any, Optional

from .Algorithm import Algorithm

def keygen(algorithm:Algorithm, key_size:Optional[int] = None) -> tuple[str,str|None]:
    """
    Generates a key (or keypair) for the specified algorithm.

    :param algorithm: The algorithm to use.
    :param key_size: If provided, overrides the size of the generated key(s), in bits, if supported by the algorithm. Typically you would not do this.
    :raises NotImplementedError: Raised when an unsupported algorithm is specified.
    :return: A tuple containing the key(s) that were generated. When returning a keypair the first value is the private key, the second value is the public key.
    """        
    match algorithm:
        case Algorithm.HS256 | Algorithm.HS384 | Algorithm.HS512:
            if key_size is None:
                match algorithm:
                    case Algorithm.HS256:
                        key_size = 256
                    case Algorithm.HS384:
                        key_size = 384
                    case Algorithm.HS512:
                        key_size = 512
            return (base64.b64encode(secrets.token_bytes(key_size)).decode('ascii'), None)
        case Algorithm.RS256 | Algorithm.RS384 | Algorithm.RS512:
            if key_size is None:
                match algorithm:
                    case Algorithm.RS256:
                        key_size = 2048
                    case Algorithm.RS384:
                        key_size = 3072
                    case Algorithm.RS512:
                        key_size = 4096
            rsa_obj = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            prikey_pem = rsa_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            pubkey_pem = rsa_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return (prikey_pem, pubkey_pem)
        case Algorithm.ES256 | Algorithm.ES384 | Algorithm.ES512:
            curve:ec.EllipticCurve
            match algorithm:
                case Algorithm.ES256:
                    curve = ec.SECP256R1()
                case Algorithm.ES384:
                    curve = ec.SECP384R1()
                case Algorithm.ES512:
                    curve = ec.SECP521R1()
            ec_obj = ec.generate_private_key(curve)
            prikey_pem = ec_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            pubkey_pem = ec_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            return (prikey_pem, pubkey_pem)
        case Algorithm.ED25519 | Algorithm.ED448:
            eddsa_obj = (ed25519.Ed25519PrivateKey if algorithm == Algorithm.ED25519 else ed448.Ed448PrivateKey).generate()
            prikey_pem = eddsa_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode('utf-8')
            pubkey_pem = eddsa_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode('utf-8')
            return (prikey_pem, pubkey_pem)
        case _:
            raise NotImplementedError(f'Unsupported Algorithm "{algorithm}"')

def tokenize(algorithm:Algorithm, private_key:str, claims:dict[str,Any], *, audience:Optional[str|list[str]] = None, issuer:Optional[str] = None) -> str:
    """
    Tokenize the provided claims, optionally injecting ``aud`` and ``iss`` claims into the claims before tokenizing.

    :param algorithm: The algorithm to use when signing the token.
    :param private_key:  The private key (or secret) used for signing.
    :param claims: The claims to be tokenized.
    :param audience: An optional value to be used as the ``aud`` claim.
    :param issuer: An optional value to be used as the ``iss`` claim.
    :return: The claims tokenized as a "compact‑serialization" JWT.
    :raises Exception: If there is an error creating a token.
    """    
    try:
        if audience is not None:
            claims |= { 'aud': audience }
        if issuer is not None:
            claims |= { 'iss': issuer }
        match algorithm:
            case Algorithm.ED25519 | Algorithm.ED448:
                return jwt.encode(claims, private_key, 'EdDSA')
            case Algorithm.HS256 | Algorithm.HS384 | Algorithm.HS512:
                return jwt.encode(claims, base64.b64decode(private_key), algorithm.value)
            case _:
                return jwt.encode(claims, private_key, algorithm.value)
    except Exception as ex:
        raise Exception()


def validate(algorithm:Algorithm, public_key:str, token:str, *, audience:Optional[str|list[str]] = None, issuer:Optional[str] = None) -> dict[str, Any]:
    """
    Verify a token and return the contained claims.

    If ``audience`` or ``issuer`` are provided `validate(...)` also checks the ``aud`` and ``iss`` claims.

    :param algorithm: The algorithm that was used to sign the token.
    :param public_key: The public key (or secret) used for verification.
    :param token:     The compact‑serialization JWT string to be validated.
    :param audience:  Expected ``aud`` claim. Omit to skip validating ``aud`` claim.
    :param issuer:    Expected ``iss`` claim. Omit to skip validating ``iss`` claim.
    :return:          The decoded claims (as a ``dict``).
    :raises Exception: If the token is invalid, expired, or claims do not match.
    """
    try:
        match algorithm:
            case Algorithm.ED25519 | Algorithm.ED448:
                return jwt.decode(token, public_key, algorithms=['EdDSA'], audience=audience, issuer=issuer, options={"verify_aud": audience is not None})
            case Algorithm.HS256 | Algorithm.HS384 | Algorithm.HS512:
                return jwt.decode(token, base64.b64decode(public_key), algorithms=[algorithm.value], audience=audience, issuer=issuer, options={"verify_aud": audience is not None})
            case _:
                return jwt.decode(token, public_key, algorithms=[algorithm.value], audience=audience, issuer=issuer)
    except Exception as ex:
        raise Exception()


__all__ = [
    'keygen',
    'tokenize',
    'validate'
]