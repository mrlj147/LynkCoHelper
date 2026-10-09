"""Fetch encrypted application keys and atomically refresh a native deployment."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile
import time

import requests
import yaml

from appsecret_bundle import MAX_BYTES, private_write, read_json, unseal, validate_secrets

REPOSITORY = 'mrlj147/LynkCoHelper'
BUNDLE_URL = 'https://github.com/' + REPOSITORY + '/releases/download/appsecret-latest/appsecret.bundle.json'


def fetch_bundle(url=BUNDLE_URL):
    deadline = time.monotonic() + 45
    with requests.get(url, timeout=(10, 20), stream=True) as response:
        response.raise_for_status()
        chunks, length = [], 0
        for chunk in response.iter_content(8192):
            length += len(chunk)
            if length > MAX_BYTES or time.monotonic() > deadline:
                raise ValueError('Encrypted AppSecret download exceeds its limits')
            chunks.append(chunk)
        data = json.loads(b''.join(chunks))
        if not isinstance(data, dict):
            raise ValueError('Encrypted AppSecret download is invalid')
        return data


def replace_preserving_permissions(path, content):
    path = Path(path)
    original = path.stat()
    if not stat.S_ISREG(original.st_mode) or path.is_symlink():
        raise ValueError('Runtime config must be a regular file')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(original.st_mode))
            current = os.fstat(stream.fileno())
            if (current.st_uid, current.st_gid) != (original.st_uid, original.st_gid):
                os.fchown(stream.fileno(), original.st_uid, original.st_gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def update_runtime_env(source, secrets):
    """Replace only existing overrides; unrelated account settings stay intact."""
    output = []
    direct = {'LYNKCO_NATIVE_APP_KEY': secrets['nativeAppKey'],
              'LYNKCO_NATIVE_APP_SECRET': secrets['nativeAppSecret']}
    for line in source.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            output.append(line)
            continue
        prefix = 'export ' if stripped.startswith('export ') else ''
        assignment = stripped[len(prefix):]
        name, separator, raw = assignment.partition('=')
        if separator and name in direct:
            output.append(prefix + name + '=' + shlex.quote(direct[name]) + '\n')
        elif separator and name == 'LYNKCO_APP_SECRETS' and raw.strip():
            parsed = shlex.split(raw)
            value = json.loads(parsed[0]) if len(parsed) == 1 else None
            if not isinstance(value, dict):
                raise ValueError('Bundled runtime override is invalid')
            value.update(secrets)
            output.append(prefix + name + '=' + shlex.quote(json.dumps(value, separators=(',', ':'))) + '\n')
        else:
            output.append(line)
    return ''.join(output)


def apply_keys(result, config_path, env_path, state_path):
    secrets = validate_secrets(result['secrets'])
    metadata = result['metadata']
    state_path = Path(state_path)
    if state_path.exists():
        state = read_json(state_path)
        if state.get('created_at', '') > metadata['created_at']:
            raise ValueError('Refusing to roll back to an older AppSecret extraction')
    config_path, env_path = Path(config_path), Path(env_path)
    original = config_path.read_bytes()
    config = yaml.safe_load(original) or {}
    if not isinstance(config, dict) or not isinstance(config.get('lynkco'), dict):
        raise ValueError('Native runtime config is invalid')
    updated = dict(config['lynkco'])
    updated.update(native_app_key=secrets['nativeAppKey'], native_app_secret=secrets['nativeAppSecret'])
    changed = updated != config['lynkco']
    env_original = env_path.read_bytes() if env_path.exists() else None
    env_updated = update_runtime_env(env_original.decode(), secrets).encode() if env_original is not None else None
    changed = changed or env_updated != env_original
    fingerprint = hashlib.sha256(json.dumps(secrets, sort_keys=True).encode()).hexdigest()
    state = {**metadata, 'applied_at': datetime.now(timezone.utc).isoformat(), 'keys_sha256': fingerprint}
    state_content = json.dumps(state, indent=2).encode() + b'\n'
    if changed:
        backup_dir = config_path.parent / '.appsecret-backups'
        backup_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(backup_dir, 0o700)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        private_write(backup_dir / (stamp + '.config.yaml'), original)
        if env_original is not None:
            private_write(backup_dir / (stamp + '.runtime.env'), env_original)
        config['lynkco'] = updated
        try:
            replace_preserving_permissions(config_path, yaml.safe_dump(config, allow_unicode=True, sort_keys=False).encode())
            if env_updated != env_original:
                replace_preserving_permissions(env_path, env_updated)
            private_write(state_path, state_content)
        except Exception:
            replace_preserving_permissions(config_path, original)
            if env_original is not None:
                replace_preserving_permissions(env_path, env_original)
            raise
        for group in ('.config.yaml', '.runtime.env'):
            previous = sorted(backup_dir.glob('*' + group))
            for path in previous[:-3]:
                path.unlink()
    else:
        private_write(state_path, state_content)
    return {'success': True, 'changed': changed, 'created_at': metadata['created_at'],
            'source_run_id': metadata['run_id'], 'keys_sha256': fingerprint}


@contextmanager
def exclusive(state_path):
    path = Path(str(state_path) + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'a') as stream:
        os.fchmod(stream.fileno(), 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--private-key', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--runtime-env', required=True)
    parser.add_argument('--state', required=True)
    args = parser.parse_args()
    try:
        with exclusive(args.state):
            result = unseal(fetch_bundle(), Path(args.private_key).read_bytes(), repository=REPOSITORY)
            report = apply_keys(result, args.config, args.runtime_env, args.state)
            print(json.dumps(report))
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError, requests.RequestException) as error:
        print(json.dumps({'success': False, 'reason': type(error).__name__, 'existing_keys_preserved': True}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
