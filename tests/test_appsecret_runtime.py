from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'LynkCoHelper' / 'tools'))
import appsecret_runtime as runtime


class RuntimeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / 'config.yaml'
        self.env = self.root / 'runtime.env'
        self.state = self.root / 'state.json'
        self.config.write_text(yaml.safe_dump({'lynkco': {'native_app_key': 'old-key', 'native_app_secret': 'old-secret',
                                                         'device_id': 'account-device', 'refresh_token': 'account-token'},
                                             'bark': {'key': 'private-notification-key'}}))
        self.config.chmod(0o640)
        self.env.write_text('LYNKCO_BARK_KEY=private-notification-key\nLYNKCO_NATIVE_APP_SECRET=old-secret\n')
        self.env.chmod(0o640)
        self.result = {'secrets': {'nativeAppKey': '123456789', 'nativeAppSecret': 'fixturesecret00000000000000000000'},
                       'metadata': {'created_at': datetime.now(timezone.utc).isoformat(), 'run_id': '123',
                                    'recipient_id': 'fixture-recipient'}}

    def apply(self):
        return runtime.apply_keys(self.result, self.config, self.env, self.state)

    def test_only_app_keys_change_and_existing_permissions_are_preserved(self):
        report = self.apply()
        self.assertTrue(report['changed'])
        config = yaml.safe_load(self.config.read_text())
        self.assertEqual(config['lynkco']['refresh_token'], 'account-token')
        self.assertEqual(config['lynkco']['device_id'], 'account-device')
        self.assertEqual(config['bark']['key'], 'private-notification-key')
        self.assertEqual(config['lynkco']['native_app_secret'], self.result['secrets']['nativeAppSecret'])
        self.assertIn('LYNKCO_BARK_KEY=private-notification-key', self.env.read_text())
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.result['secrets']['nativeAppSecret'], self.state.read_text())

    def test_repeating_the_same_keys_is_idempotent(self):
        self.apply()
        config, env = self.config.read_bytes(), self.env.read_bytes()
        report = self.apply()
        self.assertFalse(report['changed'])
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual(self.env.read_bytes(), env)

    def test_invalid_new_keys_leave_existing_configuration_untouched(self):
        original = self.config.read_bytes(), self.env.read_bytes()
        self.result['secrets']['nativeAppSecret'] = 'invalid'
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.config.read_bytes(), self.env.read_bytes()), original)

    def test_state_write_failure_restores_old_configuration(self):
        original = self.config.read_bytes(), self.env.read_bytes()
        real = runtime.private_write
        def failing(path, content):
            if Path(path) == self.state:
                raise OSError('fixture storage error')
            return real(path, content)
        with patch('appsecret_runtime.private_write', side_effect=failing), self.assertRaises(OSError):
            self.apply()
        self.assertEqual((self.config.read_bytes(), self.env.read_bytes()), original)

    def test_older_extraction_cannot_roll_back_current_keys(self):
        self.state.write_text(json.dumps({'created_at': '2099-01-01T00:00:00+00:00'}))
        original = self.config.read_bytes(), self.env.read_bytes()
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.config.read_bytes(), self.env.read_bytes()), original)

    def test_bundle_override_preserves_unrelated_fields(self):
        source = 'LYNKCO_APP_SECRETS=\'{"nativeAppCode":"keep-code","nativeAppSecret":"old"}\'\n'
        value = runtime.update_runtime_env(source, self.result['secrets'])
        self.assertIn('keep-code', value)
        self.assertNotIn('"old"', value)


if __name__ == '__main__':
    unittest.main()
