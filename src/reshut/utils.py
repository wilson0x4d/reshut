# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from datetime import datetime, timezone
import jwt
from jwt.types import Options
import secrets
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


def tokenize(algorithm:Algorithm, private_key:str, claims:dict[str,Any],
        *,
        audience:Optional[str|list[str]] = None,
        issuer:Optional[str] = None,
        subject:Optional[str] = None,
        expiry:Optional[int] = None,
        not_before:Optional[int] = None,
        issued_at:Optional[int] = None,
        token_id:Optional[str] = None
    ) -> str:
    """
    Tokenize the provided claims, optionally accepting standard JWT claims as args and injecting them anew on top of existing claims.

    :param algorithm: The algorithm to use when signing the token.
    :param private_key: The private key (or secret) used for signing.
    :param claims: The claims to be tokenized.
    :param audience: Optional ``aud`` claim - a string or list of strings.
    :param issuer: Optional ``iss`` claim.
    :param subject: Optional ``sub`` claim.
    :param expiry: Optional ``exp`` claim (unix timestamp).
    :param not_before: Optional ``nbf`` claim (unix timestamp).
    :param issued_at: Optional ``iat`` claim (unix timestamp). If omitted and not present in *claims*, the current UTC time is used.
    :param token_id: Optional ``jti`` claim.
    :return: The claims encoded as a compact-serialization JWT.
    :raises Exception: If an error occurs while creating the token.
    """    
    missing_claims = list[str]()
    inject_claims = dict[str,Any]()
    #
    if audience is not None:
        inject_claims['aud'] = audience
    elif 'aud' not in claims:
        missing_claims.append('aud')
    #
    if issuer is not None:
        inject_claims['iss'] = issuer
    elif 'iss' not in claims:
        missing_claims.append('iss')
    #
    if subject is not None:
        inject_claims['sub'] = subject
    elif 'sub' not in claims:
        missing_claims.append('sub')
    #
    if expiry is not None:
        inject_claims['exp'] = expiry
    elif 'exp' not in claims:
        missing_claims.append('exp')
    #
    if issued_at is not None:
        inject_claims['iat'] = issued_at
    elif 'iat' not in claims:
        inject_claims['iat'] = int(datetime.now(timezone.utc).timestamp())
    #
    # optional/situational
    #
    if not_before is not None:
        inject_claims['nbf'] = not_before
    if token_id is not None:
        inject_claims['jti'] = token_id
    #
    if len(inject_claims) > 0:
        claims |= inject_claims
    #
    match algorithm:
        case Algorithm.ED25519 | Algorithm.ED448:
            return jwt.encode(claims, private_key, 'EdDSA')
        case Algorithm.HS256 | Algorithm.HS384 | Algorithm.HS512:
            return jwt.encode(claims, base64.b64decode(private_key), algorithm.value)
        case _:
            return jwt.encode(claims, private_key, algorithm.value)

def validate(algorithm:Algorithm, public_key:str, token:str,
        *,
        enforce:bool = True,
        audience:Optional[str] = None,
        issuer:Optional[str] = None,
        subject:Optional[str] = None,
    ) -> dict[str, Any]:
    """
    Verify a token and return the contained claims.

    If "standard claims" are provided as args, the function also checks that those claims match.

    Other standard claims such as ``nbf`` and are automatically enforced unless ``enforce_claims=False`` is specified.

    :param algorithm:   The algorithm that was used to sign the token.
    :param public_key:  The public key (or secret) used for verification.
    :param token:       The compact‑serialization JWT string to be validated.
    :param enforce:     Indicates that "standard claims enforcement" should be performed, for example that ``exp`` is not validated before the indicated time or that ``exp`` is not in the past.
    :param audience:    Expected ``aud`` claim. Omit to skip validating ``aud`` claim.
    :param issuer:      Expected ``iss`` claim. Omit to skip validating ``iss`` claim.
    :param subject:     Expected ``sub`` claim. Omit to skip validating ``sub`` claim.
    :return:            The decoded claims (as a ``dict``).
    :raises Exception:  If the token is invalid, fails standards-enforcement, or claims do not match expected values.
    """
    tsnow = int(datetime.now().timestamp())
    options = Options(
        verify_signature=enforce,
        strict_aud=False,
        verify_aud=False,
        verify_exp=False,
        verify_iat=False,
        verify_iss=False,
        verify_jti=False,
        verify_nbf=False,
        verify_sub=False,
        require=[],
        enforce_minimum_key_length=False
    )
    claims:dict[str,Any]
    match algorithm:
        case Algorithm.ED25519 | Algorithm.ED448:
            claims = jwt.decode(token, public_key, algorithms=['EdDSA'], audience=audience, issuer=issuer, options=options)
        case Algorithm.HS256 | Algorithm.HS384 | Algorithm.HS512:
            claims = jwt.decode(token, base64.b64decode(public_key), algorithms=[algorithm.value], audience=audience, issuer=issuer, options=options)
        case _:
            claims = jwt.decode(token, public_key, algorithms=[algorithm.value], audience=audience, issuer=issuer, options=options)
    if audience is not None:
        aud = claims.get('aud', None)
        if aud is None or (isinstance(aud, list) and audience not in aud) or aud != audience:
            raise Exception('audience is incorrect.')
    if issuer is not None and claims.get('iss', None) != issuer:
        raise Exception('issuer is incorrect.')
    if subject is not None and claims.get('sub', None) != subject:
        raise Exception('subject is incorrect.')
    if enforce:
        if claims.get('nbf', tsnow) > tsnow:
            raise Exception('token cannot be used yet (nbf check failed)')
        if claims.get('exp', tsnow) < tsnow:
            raise Exception('token has expired (exp check failed)')
    return claims


__all__ = [
    'keygen',
    'tokenize',
    'validate'
]