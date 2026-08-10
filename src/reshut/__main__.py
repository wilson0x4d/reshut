# SPDX-FileCopyrightText: © 2026 Shaun Wilson
# SPDX-License-Identifier: MIT

import argparse
import json
from pathlib import Path
import sys
from typing import cast
from .jwk import JWK
from .utils import Algorithm, keygen, tokenize, validate


def __write_key_files(basename: str, key: str) -> None:
    base_path = Path(basename)
    out_path = base_path.with_suffix('.jwk')
    out_path.write_text(key, encoding='utf-8')
    print(f'Wrote key to {out_path}')


def __cmd_keygen(args: argparse.Namespace) -> None:
    try:
        alg = Algorithm(str(args.type).upper())
    except ValueError as exc:
        sys.stderr.write(f'Unsupported algorithm: {args.type}\n')
        raise SystemExit(2) from exc
    key = keygen(alg)
    key_json = json.dumps(key, indent=None, separators=(',', ':'))
    __write_key_files(args.output, key_json)


def __read_key_file(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8').strip()
    except OSError as exc:
        sys.stderr.write(f'Unable to read key file {path}: {exc}\n')
        raise SystemExit(3) from exc


def __cmd_tokenize(args: argparse.Namespace) -> None:
    try:
        claims = json.loads(args.claims)
        if not isinstance(claims, dict):
            raise TypeError
    except Exception as exc:
        sys.stderr.write('Claims must be a JSON object.\n')
        raise SystemExit(5) from exc
    key_json = __read_key_file(Path(args.key))
    key = cast(JWK, json.loads(key_json))
    token = tokenize(key, claims)
    print(token)


def __cmd_validate(args: argparse.Namespace) -> None:
    key_json = __read_key_file(Path(args.key))
    key = cast(JWK, json.loads(key_json))
    try:
        claims = validate(key, args.token)
        print(json.dumps(claims, indent=2, sort_keys=True))
    except Exception as exc:
        sys.stderr.write(f'Validation failed: {exc}\n')
        raise SystemExit(7) from exc


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        prog='python -m reshut',
        description='Utility for generating keys, creating and validating JWTs.'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # reshut-keygen
    reshut_keygen = subparsers.add_parser('keygen', help='Generate a secret or key-pair.')
    reshut_keygen.add_argument('--type', required=True, help='Algorithm name (e.g. HS256, RS256).')
    reshut_keygen.add_argument('--output', required=True, help='Base filename (prefix) for generated key files.')
    reshut_keygen.set_defaults(func=__cmd_keygen)

    # reshut-tokenize
    reshut_tokenize = subparsers.add_parser('tokenize', help='Create a JWT from claims.')
    reshut_tokenize.add_argument('--key', required=True, help='Path to the JWK key file.')
    reshut_tokenize.add_argument('--claims', required=True, help='JSON string representing the claim set.')
    reshut_tokenize.set_defaults(func=__cmd_tokenize)

    # reshut-validate
    reshut_validate = subparsers.add_parser('validate', help='Validate a JWT.')
    reshut_validate.add_argument('--key', required=True, help='Path to the JWK key file.')
    reshut_validate.add_argument('--token', required=True, help='JWT string to validate.')
    reshut_validate.set_defaults(func=__cmd_validate)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main(sys.argv[1:])
