# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import argparse
import json
import sys
from typing import Optional
from pathlib import Path

from .utils import Algorithm, keygen, tokenize, validate


def __write_key_files(basename:str, prikey:str, pubkey:Optional[str]) -> None:
    base_path = Path(basename)
    if pubkey is None:
        # shared secret
        out_path = base_path.with_suffix('.b64')
        out_path.write_text(prikey, encoding='utf-8')
        print(f'Wrote secret key to {out_path}')
    else:
        # keypair
        prikey_path = base_path.with_name(f'{base_path.name}_prikey.pem')
        pubkey_path = base_path.with_name(f'{base_path.name}_pubkey.pem')
        prikey_path.write_text(prikey, encoding='utf-8')
        print(f'Wrote private key to {prikey_path}')
        pubkey_path.write_text(pubkey, encoding='utf-8')
        print(f'Wrote public  key to {pubkey_path}')

def __cmd_keygen(args: argparse.Namespace) -> None:
    try:
        alg = Algorithm(str(args.type).upper())
    except ValueError as exc:
        sys.stderr.write(f'Unsupported algorithm: {args.type}\n')
        raise SystemExit(2) from exc

    prikey, pubkey = keygen(alg)          # type: ignore[arg-type]
    __write_key_files(args.output, prikey, pubkey)


def __read_key_file(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8').strip()
    except OSError as exc:
        sys.stderr.write(f'Unable to read key file {path}: {exc}\n')
        raise SystemExit(3) from exc


def __cmd_tokenize(args: argparse.Namespace) -> None:
    try:
        alg = Algorithm(str(args.type).upper())
    except ValueError as exc:
        sys.stderr.write(f'Unsupported algorithm: {args.type}\n')
        raise SystemExit(4) from exc
    try:
        claims = json.loads(args.claims)
        if not isinstance(claims, dict):
            raise TypeError
    except Exception as exc:
        sys.stderr.write('Claims must be a JSON object.\n')
        raise SystemExit(5) from exc
    private_key = __read_key_file(Path(args.key))
    token = tokenize(alg, private_key, claims)
    print(token)


def __cmd_validate(args: argparse.Namespace) -> None:
    try:
        alg = Algorithm(str(args.type).upper())
    except ValueError as exc:
        sys.stderr.write(f'Unsupported algorithm: {args.type}\n')
        raise SystemExit(6) from exc
    public_key = __read_key_file(Path(args.key))
    try:
        claims = validate(alg, public_key, args.token)
    except Exception as exc:
        sys.stderr.write(f'Validation failed: {exc}\n')
        raise SystemExit(7) from exc

    print(json.dumps(claims, indent=2, sort_keys=True))


def main(argv:list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog='python -m reshut',
        description='Utility for generating keys, creating and validating JWTs.'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # reshut-keygen
    reshut_keygen = subparsers.add_parser('keygen', help='Generate a secret or key‑pair.')
    reshut_keygen.add_argument('--type', required=True, help='Algorithm name (e.g. HS256, RS256).')
    reshut_keygen.add_argument('--output', required=True, help='Base filename (prefix) for generated key files.')
    reshut_keygen.set_defaults(func=__cmd_keygen)

    # reshut-tokenize
    reshut_tokenize = subparsers.add_parser('tokenize', help='Create a JWT from claims.')
    reshut_tokenize.add_argument('--type', required=True, help='Algorithm name.')
    reshut_tokenize.add_argument('--claims', required=True, help='JSON string representing the claim set.')
    reshut_tokenize.add_argument('--key', required=True, help='Path to the private key / secret file.')
    reshut_tokenize.set_defaults(func=__cmd_tokenize)

    # reshut-validate
    reshut_validate = subparsers.add_parser('validate', help='Validate a JWT.')
    reshut_validate.add_argument('--type', required=True, help='Algorithm name.')
    reshut_validate.add_argument('--token', required=True, help='JWT string to validate.')
    reshut_validate.add_argument('--key', required=True, help='Path to the public key / secret file.')
    reshut_validate.set_defaults(func=__cmd_validate)

    args = parser.parse_args(argv)
    args.func(args)          # type: ignore[attr-defined]

if __name__ == '__main__':
    main(sys.argv[1:])
