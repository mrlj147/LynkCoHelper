from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.PublicKey import RSA

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'LynkCoHelper' / 'tools'))
import appsecret_bundle as bundle
import appsecret_core as core


class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(3072)
        cls.public = cls.key.public_key().export_key()
        cls.private = cls.key.export_key()

    def setUp(self):
        self.now = datetime(2026, 10, 9, 1, tzinfo=timezone.utc)
        self.secrets = {'nativeAppKey': '123456789', 'nativeAppSecret': 'fixturesecret00000000000000000000'}

    def sealed(self, **kwargs):
        return bundle.seal(self.secrets, self.public, repository='mrlj147/LynkCoHelper',
                           run_id=123, commit='a' * 40, now=kwargs.get('now', self.now))

    def opened(self, value, **kwargs):
        return bundle.unseal(value, self.private, repository=kwargs.get('repository', 'mrlj147/LynkCoHelper'),
                             now=kwargs.get('now', self.now))

    def test_round_trip_contains_only_extracted_app_keys(self):
        data = {**self.secrets, 'token': 'personal-account-fixture', 'password': 'private-password'}
        envelope = bundle.seal(data, self.public, repository='mrlj147/LynkCoHelper',
                               run_id=123, commit='a' * 40, now=self.now)
        source = json.dumps(envelope)
        for private_value in list(data.values()):
            self.assertNotIn(private_value, source)
        self.assertEqual(self.opened(envelope)['secrets'], self.secrets)

    def test_modified_ciphertext_and_metadata_fail(self):
        for field in ('tag', 'ciphertext', 'wrapped_key', 'commit', 'run_id'):
            with self.subTest(field=field):
                data = self.sealed()
                data[field] = ('b' if data[field][0] != 'b' else 'c') + data[field][1:]
                with self.assertRaises(ValueError):
                    self.opened(data)

    def test_source_and_recipient_must_match(self):
        with self.assertRaises(ValueError):
            self.opened(self.sealed(), repository='another/repository')
        data = self.sealed()
        data['recipient_id'] = '0' * 64
        with self.assertRaises(ValueError):
            self.opened(data)

    def test_old_and_future_keys_are_rejected(self):
        for instant in (self.now - timedelta(hours=73), self.now + timedelta(minutes=6)):
            with self.subTest(instant=instant), self.assertRaises(ValueError):
                self.opened(self.sealed(now=instant))

    def test_invalid_extraction_never_creates_a_bundle(self):
        for data in ({}, {'nativeAppKey': True, 'nativeAppSecret': 'a' * 32},
                     {'nativeAppKey': '123456789', 'nativeAppSecret': 'bad\nsecret'}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                bundle.seal(data, self.public, repository='mrlj147/LynkCoHelper',
                            run_id=123, commit='a' * 40, now=self.now)

    def test_private_files_are_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'keys.json'
            target.write_bytes(b'previous')
            bundle.private_write(target, b'new')
            self.assertEqual(target.read_bytes(), b'new')
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_ci_logs_hide_the_entire_extracted_value(self):
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'true'}):
            for value in self.secrets.values():
                masked = core.mask_secret(value)
                self.assertNotIn(value[:3], masked)
                self.assertNotIn(value[-2:], masked)

    def test_workflow_has_daily_delivery_and_no_public_plaintext_link(self):
        import yaml
        text = (ROOT / '.github/workflows/extract-appsecret.yml').read_text()
        workflow = yaml.safe_load(text)
        trigger = workflow.get('on', workflow.get(True))
        self.assertEqual(trigger['schedule'], [{'cron': '37 16 * * *'}])
        self.assertNotIn('cloudcpp', text)
        self.assertNotIn('upload-artifact', text)
        steps = workflow['jobs']['extract']['steps']
        encrypt = next(i for i, step in enumerate(steps) if step.get('name') == 'Encrypt and validate extracted keys')
        publish = next(i for i, step in enumerate(steps) if step.get('name') == 'Publish encrypted latest keys')
        self.assertLess(encrypt, publish)
        self.assertNotIn('if', steps[publish])
        self.assertEqual(steps[0]['with']['persist-credentials'], False)
        self.assertEqual(steps[-2]['if'], 'always()')


if __name__ == '__main__':
    unittest.main()
