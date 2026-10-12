"""Regression coverage for changing APK key-class names and safe cached candidates."""
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'LynkCoHelper/tools'))
import appsecret_core as core


class KeyClassTests(unittest.TestCase):
    def scan(self, data):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.apk'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('classes.dex', data)
            return core._scan_apk_for_key_classes(path)

    def test_scan_follows_obfuscated_reference_instead_of_definition_cluster(self):
        definitions = b''.join(b'Lcom/safe/cons/LynkCoConstants$' + name + b';' for name in (b'a', b'b', b'f', b'g'))
        for name in (b'g', b'f', b'aa'):
            with self.subTest(name=name):
                data = definitions + b'\x00' * 1500 + b'Lcom/safe/cons/LynkCoConstants$' + name + b';'
                self.assertEqual(self.scan(data), ['com.safe.cons.LynkCoConstants$' + name.decode()])

    def test_named_classes_do_not_hide_an_isolated_key_reference(self):
        data = b'Lcom/safe/cons/LynkCoConstants$WeexUrl;Lcom/safe/cons/LynkCoConstants$f;Lcom/safe/cons/LynkCoConstants$ModuleEvent;'
        self.assertEqual(self.scan(data), ['com.safe.cons.LynkCoConstants$f'])

    def test_unrecognized_apk_does_not_fall_back_to_old_class(self):
        self.assertEqual(self.scan(b'no key-class references'), [])
        with patch.object(core, '_auto_candidates', {'resolved': False, 'list': []}), \
             patch.object(core, 'auto_detect_candidates', return_value=[]), self.assertRaises(SystemExit):
            core.get_candidates()

    def test_cached_candidates_are_used_without_pulling_apk(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'keyclass-v4.2.8.txt').write_text('com.safe.cons.LynkCoConstants$f\n')
            with patch.object(core, 'TOOLS_DIR', folder), \
                 patch.object(core, 'adb', return_value='versionName=4.2.8') as adb, \
                 patch.object(core.subprocess, 'run') as run:
                self.assertEqual(core.auto_detect_candidates(), ['com.safe.cons.LynkCoConstants$f'])
            run.assert_not_called()
            self.assertEqual(adb.call_count, 1)

    def test_invalid_cache_is_not_accepted_as_debugger_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'keyclass-v4.2.8.txt').write_text('com.safe.cons.LynkCoConstants$f\nprint private.value\n')
            with patch.object(core, 'TOOLS_DIR', folder), \
                 patch.object(core, 'adb', side_effect=['versionName=4.2.8', '']):
                self.assertEqual(core.auto_detect_candidates(), [])


if __name__ == '__main__':
    unittest.main()
