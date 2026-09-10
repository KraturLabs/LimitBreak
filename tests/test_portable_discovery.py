"""Full production discovery on a synthetic PE built with the normal toolchain.

The fixture is read as data, never loaded or executed. Its assembly is fixed
and independent of the production schema during build/test execution.
"""
from pathlib import Path
import unittest
import test_discovery as mutations
from test_native_discovery import native, compare
from discovery_image import file_image
from discover import Discovery


class PortableDiscoveryTests(mutations.CaptureTests):
    __unittest_skip__ = False
    __unittest_skip_why__ = ''

    @classmethod
    def setUpClass(cls):
        path = mutations.ROOT / 'build/Release/discovery_fixture.dll'
        if not path.exists():
            raise AssertionError('Build discovery_fixture before running the complete suite')
        disk = file_image(path)
        file_bytes = path.read_bytes()
        raw = bytearray(disk.size)
        raw[:disk.header_size] = file_bytes[:disk.header_size]
        for section in disk.sections:
            size = min(section['size'], section['raw_size'])
            raw[section['rva']:section['rva']+size] = file_bytes[section['offset']:section['offset']+size]
        cls.raw, cls.base = bytes(raw), disk.base
        cls.baseline = Discovery(cls.image(cls.raw)).run()
        if cls.baseline['status'] != 'discovered':
            raise AssertionError(cls.baseline)
        cls.found = cls.baseline['matches'][0]

    def run_image(self, raw):
        expected = super().run_image(raw)
        compare(self, expected, native(raw, self.base))
        return expected

    def test_baseline_addresses(self):
        super().test_baseline_addresses()
        # Independent assembly/link-layout oracles; never production inputs.
        self.assertEqual(self.rva('initializer'), 0x1000)
        self.assertEqual(self.rva('query_return'), 0x1027)
        self.assertEqual([int(v['rva'], 16) for v in self.found['cap_operands']], [0x1043, 0x104c])
        compare(self, self.baseline, native(self.raw, self.base))


if __name__ == '__main__':
    unittest.main()
