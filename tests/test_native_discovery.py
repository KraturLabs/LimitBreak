"""Run the native reader on the same caller-supplied in-memory mutation fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_discovery as fixtures
from discovery_image import DumpImage
from discover import Discovery

EXE = fixtures.ROOT/'build/Release/discovery_check.exe'


def native(raw, base):
    with tempfile.TemporaryDirectory(prefix='limitbreak-native-test-') as directory:
        path = Path(directory)/'image.bin'
        path.write_bytes(raw)
        completed = subprocess.run([str(EXE), str(path), hex(base)], capture_output=True,
                                   text=True, timeout=20, check=False)
        if completed.returncode not in (0, 2):
            raise AssertionError(completed.stderr or completed.stdout)
        report = json.loads(completed.stdout)
        if (completed.returncode == 0) != (report['status'] == 'discovered'):
            raise AssertionError(report)
        return report


def compare(test, expected, actual):
    test.assertEqual(actual['status'], expected['status'], actual)
    test.assertEqual(actual['validated_count'], expected['validated_count'], actual)
    if expected['status'] == 'discovered':
        found = expected['matches'][0]
        for key, rva in actual['addresses'].items():
            test.assertEqual(rva, found[key]['rva'], key)
        test.assertEqual(actual['cap_operands'], [a['rva'] for a in found['cap_operands']])
        test.assertEqual(actual['pool_globals'], [a['head']['rva'] for a in found['pool_globals']])
        test.assertEqual(actual['wrappers'], [a['rva'] for a in found['wrappers']])
        test.assertEqual(actual['cap_mib'], found['cap_mib'])


@unittest.skipUnless(EXE.exists(), 'build the native discovery checker')
class NativeMutationTests(fixtures.CaptureTests):
    def run_image(self, raw):
        expected = super().run_image(raw)
        compare(self, expected, native(raw, self.base))
        return expected

    def test_baseline_addresses(self):
        super().test_baseline_addresses()
        compare(self, self.baseline, native(self.raw, self.base))


@unittest.skipUnless(EXE.exists() and os.environ.get('LIMITBREAK_TEST_DUMP'), 'native build and caller-supplied dump required')
class NativeDumpTests(unittest.TestCase):
    def test_dump_matches_python(self):
        owner = DumpImage(os.environ['LIMITBREAK_TEST_DUMP'])
        try:
            expected = Discovery(owner.image).run()
            # Transient test input, removed immediately; not a new durable capture.
            raw = owner.image.reader(0, owner.image.size)
            compare(self, expected, native(raw, owner.image.base))
        finally:
            owner.close()


if __name__ == '__main__':
    unittest.main()
