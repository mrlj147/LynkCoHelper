import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'LynkCoHelper/tools'))
import appsecret_core as core


class VerifiedAPKTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.data = b'fixture official APK bytes'
        self.latest = {'data': {'androidNewestVersion': 'V4.2.8'}}
        self.release = {'tag_name': 'apk-v4.2.8', 'assets': [{'name': 'lynkco-v4.2.8.apk',
                         'digest': 'sha256:' + hashlib.sha256(self.data).hexdigest()}]}

    def read_source(self, *, downloaded=None, release=None):
        def download(url, destination, size):
            self.assertIn('/apk-v4.2.8/lynkco-v4.2.8.apk', url)
            Path(destination).write_bytes(downloaded if downloaded is not None else self.data)
            return True
        responses = [io.BytesIO(json.dumps(self.latest).encode()), io.BytesIO(json.dumps(release or self.release).encode())]
        with patch('appsecret_core.TOOLS_DIR', str(self.folder)), \
             patch('appsecret_core.urllib.request.urlopen', side_effect=responses), \
             patch('appsecret_core._try_download', side_effect=download):
            return core._latest_verified_release_apk()

    def test_source_must_match_current_official_version_and_digest(self):
        result = self.read_source()
        self.assertEqual(Path(result).read_bytes(), self.data)

    def test_modified_download_is_rejected_and_removed(self):
        with self.assertRaises(RuntimeError):
            self.read_source(downloaded=b'tampered APK')
        self.assertFalse((self.folder / 'lynkco-v4.2.8.apk').exists())

    def test_old_release_is_not_accepted_as_latest(self):
        release = dict(self.release, tag_name='apk-v4.2.7')
        self.assertIsNone(self.read_source(release=release))

    def test_ci_metadata_auth_is_not_forwarded_to_redirects(self):
        response = Mock(status_code=200)
        response.json.return_value = self.release
        def download(url, destination, size):
            Path(destination).write_bytes(self.data)
            return True
        with patch.dict('os.environ', {'GH_TOKEN': 'fixture-api-token'}), \
             patch('appsecret_core.TOOLS_DIR', str(self.folder)), \
             patch('appsecret_core.urllib.request.urlopen', return_value=io.BytesIO(json.dumps(self.latest).encode())), \
             patch('requests.get', return_value=response) as get, \
             patch('appsecret_core._try_download', side_effect=download):
            self.assertTrue(core._latest_verified_release_apk())
        self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_ci_crash_diagnostics_never_emit_raw_log_values(self):
        from contextlib import redirect_stdout
        output = io.StringIO()
        crash = 'Fatal signal SIGSEGV in libndk_translation.so; private-secret-fixture'
        with patch.dict('os.environ', {'GITHUB_ACTIONS': 'true'}), \
             patch('appsecret_core.adb', side_effect=['', 'x86_64,arm64-v8a', crash, 'reason=3 (LOW_MEMORY) status=9 private-secret-fixture']), \
             redirect_stdout(output):
            core._dump_device_diagnostics('fixture')
        self.assertNotIn('private-secret-fixture', output.getvalue())
        self.assertIn('SIGSEGV', output.getvalue())
        self.assertIn('libndk_translation.so', output.getvalue())
        self.assertIn('LOW_MEMORY', output.getvalue())


if __name__ == '__main__':
    unittest.main()
