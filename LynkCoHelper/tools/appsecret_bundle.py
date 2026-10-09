"""Seal extracted app keys for private consumption without publishing plaintext."""
import argparse
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

MAX_BYTES = 65536


def private_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError('AppSecret document exceeds size limit')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('AppSecret document must be an object')
    return data


def validate_secrets(value):
    if not isinstance(value, dict):
        raise ValueError('Extracted AppSecret fields are missing')
    patterns = {'nativeAppKey': r'[0-9]{6,16}', 'nativeAppSecret': r'[A-Za-z0-9]{16,64}'}
    result = {}
    for field, pattern in patterns.items():
        item = value.get(field)
        if not isinstance(item, str) or not re.fullmatch(pattern, item):
            raise ValueError('Invalid extracted field: ' + field)
        result[field] = item
    return result


def recipient_id(key):
    return hashlib.sha256(key.public_key().export_key(format='DER')).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def seal(secrets, public_pem, *, repository, run_id, commit, now=None):
    secrets = validate_secrets(secrets)
    key = RSA.import_key(public_pem)
    if key.has_private() or key.size_in_bits() < 3072:
        raise ValueError('Expected an RSA public key of at least 3072 bits')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid source repository')
    if not str(run_id).isdigit() or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Invalid workflow provenance')
    now = now or datetime.now(timezone.utc)
    metadata = {'version': 1, 'repository': repository, 'run_id': str(run_id),
                'commit': commit, 'created_at': now.astimezone(timezone.utc).isoformat(),
                'recipient_id': recipient_id(key)}
    session_key = get_random_bytes(32)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    cipher.update(_canonical(metadata))
    ciphertext, tag = cipher.encrypt_and_digest(_canonical({'secrets': secrets}))
    encoded = lambda value: base64.b64encode(value).decode('ascii')
    return {**metadata, 'wrapped_key': encoded(PKCS1_OAEP.new(key, hashAlgo=SHA256).encrypt(session_key)),
            'nonce': encoded(cipher.nonce), 'ciphertext': encoded(ciphertext), 'tag': encoded(tag)}


def unseal(bundle, private_pem, *, repository, max_age_hours=72, now=None):
    if not isinstance(bundle, dict):
        raise ValueError('Invalid encrypted AppSecret bundle')
    metadata_fields = ('version', 'repository', 'run_id', 'commit', 'created_at', 'recipient_id')
    try:
        metadata = {field: bundle[field] for field in metadata_fields}
        key = RSA.import_key(private_pem)
        if not key.has_private() or key.size_in_bits() < 3072:
            raise ValueError('Expected a private recipient key')
        if metadata['version'] != 1 or metadata['repository'] != repository or metadata['recipient_id'] != recipient_id(key):
            raise ValueError('AppSecret bundle recipient or source mismatch')
        timestamp = datetime.fromisoformat(metadata['created_at'])
        if timestamp.tzinfo is None:
            raise ValueError('Missing AppSecret timestamp timezone')
        now = now or datetime.now(timezone.utc)
        age = now - timestamp
        if age < timedelta(minutes=-5) or age > timedelta(hours=max_age_hours):
            raise ValueError('AppSecret bundle is stale or from the future')
        decode = lambda field: base64.b64decode(bundle[field], validate=True)
        session_key = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(decode('wrapped_key'))
        nonce, tag = decode('nonce'), decode('tag')
        if len(nonce) != 12 or len(tag) != 16:
            raise ValueError('Invalid AppSecret encryption parameters')
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(_canonical(metadata))
        plaintext = cipher.decrypt_and_verify(decode('ciphertext'), tag)
        secrets = validate_secrets(json.loads(plaintext)['secrets'])
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError('Encrypted AppSecret bundle validation failed') from None
    return {'secrets': secrets, 'metadata': metadata}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    encrypt = commands.add_parser('seal')
    encrypt.add_argument('--env-file', required=True)
    encrypt.add_argument('--public-key', required=True)
    encrypt.add_argument('--output', required=True)
    decrypt = commands.add_parser('unseal')
    decrypt.add_argument('--bundle', required=True)
    decrypt.add_argument('--private-key', required=True)
    decrypt.add_argument('--output', required=True)
    decrypt.add_argument('--repository', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'seal':
            data = read_json(args.env_file)
            bundle = seal(data.get('secrets'), Path(args.public_key).read_bytes(),
                          repository=os.environ['GITHUB_REPOSITORY'], run_id=os.environ['GITHUB_RUN_ID'],
                          commit=os.environ['GITHUB_SHA'])
            private_write(args.output, _canonical(bundle) + b'\n')
            print('Encrypted AppSecret bundle ready; plaintext has not been published.')
        else:
            result = unseal(read_json(args.bundle), Path(args.private_key).read_bytes(), repository=args.repository)
            private_write(args.output, _canonical(result) + b'\n')
            print('AppSecret bundle validated and saved privately.')
    except (OSError, ValueError, KeyError):
        raise SystemExit('AppSecret bundle operation failed; no plaintext output.') from None


if __name__ == '__main__':
    main()
