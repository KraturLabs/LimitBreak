"""Synthetic policy tests and optional caller-supplied image mutation tests."""
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from discover import Discovery, validate_layout
from discovery_image import Image, Refused, DumpImage, LiveImage


def pools(capacity, head=0x20000000):
    budgets = [capacity*1048576, 10*1048576, 16*1048576, 4096, 4096]
    result = [None]*5
    for i in (0, 1, 3, 2, 4):
        result[i] = (head, head+budgets[i]-144)
        head += budgets[i]
    return result


class PolicyTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'Windows external reader')
    def test_runtime_reader_refuses_nonclient(self):
        with self.assertRaisesRegex(Refused, 'exactly one loaded FFXiMain'):
            LiveImage(os.getpid())

    def test_stock_expanded_and_fallback(self):
        for cap, capacity in ((256, 192), (256, 64), (384, 320), (384, 64)):
            self.assertIn(str(capacity), validate_layout(pools(capacity), cap))
        self.assertIn('uninitialized', validate_layout([(0, 0)]*5, 256))

    def test_cap_disagreement(self):
        for cap, capacity in ((384, 192), (256, 320), (256, 256), (448, 384), (384, 384)):
            with self.assertRaises(Refused):
                validate_layout(pools(capacity), cap)

    def test_malformed_layouts(self):
        for cap, capacity in ((256, 192), (384, 64), (384, 320)):
            for i in range(5):
                for replacement in ((0, 0), (1, 17), (0x10000, 0x10000)):
                    bad = pools(capacity)
                    bad[i] = replacement
                    with self.assertRaises(Refused):
                        validate_layout(bad, cap)
            bad = pools(capacity)
            bad[4] = bad[3]
            with self.assertRaises(Refused):
                validate_layout(bad, cap)

    def test_invalid_headers(self):
        for raw in (bytes(64), b'MZ'+bytes(62)):
            with self.assertRaises(Refused):
                Image(lambda p, n: raw[p:p+n], 0x10000000, 'synthetic')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'empty.dmp'
            path.write_bytes(b'')
            with self.assertRaisesRegex(Refused, 'truncated minidump'):
                DumpImage(path)


@unittest.skipUnless(os.environ.get('LIMITBREAK_TEST_CAPTURE') and os.environ.get('LIMITBREAK_TEST_BASE'),
                     'set LIMITBREAK_TEST_CAPTURE and LIMITBREAK_TEST_BASE for image mutation tests')
class CaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = Path(os.environ['LIMITBREAK_TEST_CAPTURE']).read_bytes()
        cls.base = int(os.environ['LIMITBREAK_TEST_BASE'], 0)
        cls.baseline = Discovery(cls.image(cls.raw)).run()
        if cls.baseline['status'] != 'discovered':
            raise AssertionError(cls.baseline)
        cls.found = cls.baseline['matches'][0]

    @classmethod
    def image(cls, raw):
        return Image(lambda p, n: bytes(raw[p:p+n]), cls.base, 'caller-supplied image in memory')

    def rva(self, key):
        return int(self.found[key]['rva'], 16)

    def run_image(self, raw):
        return Discovery(self.image(raw)).run()

    def reject(self, raw, reason=None):
        report = self.run_image(raw)
        self.assertEqual(report['status'], 'refused', report)
        if reason:
            self.assertIn(reason, json.dumps(report))

    def set_pools(self, raw, capacity):
        g = int(self.found['pool_globals'][0]['head']['rva'], 16)
        raw[g:g+40] = b''.join(struct.pack('<II', *p) for p in pools(capacity))

    def test_baseline_addresses(self):
        # Check address relationships without an oracle tied to a particular build.
        for key in ('initializer', 'query_return', 'builder', 'reverse_allocator'):
            self.assertEqual(int(self.found[key]['va'], 16), self.base + self.rva(key))
        self.assertEqual(len(self.found['pool_globals']), 5)
        self.assertEqual(self.baseline['validated_count'], 1)

    def test_changed_hash_is_not_gate(self):
        raw = bytearray(self.raw)
        raw[0x30] ^= 1  # Unused DOS-header field, not structural evidence.
        self.assertEqual(self.run_image(raw)['status'], 'discovered')

    def collected_graph(self):
        class Collect(Discovery):
            def __init__(self, image):
                self.instructions, self.tables = {}, set()
                super().__init__(image)

            def match(self, *args, **kwargs):
                values, labels, instructions = super().match(*args, **kwargs)
                for ins in instructions:
                    self.instructions[ins.address] = ins
                if 'table' in values:
                    self.tables.add(values['table'])
                return values, labels, instructions
        discovery = Collect(self.image(self.raw))
        self.assertEqual(discovery.run()['status'], 'discovered')
        return discovery

    def translate_operands(self, raw, graph, low, high, delta):
        for ins in graph.instructions.values():
            for size, offset, relative in ((ins.disp_size, ins.disp_offset, False),
                    (ins.imm_size, ins.imm_offset, ins.mnemonic == 'call' or ins.mnemonic.startswith('j'))):
                if size == 4 and not relative:
                    at = ins.address-self.base+offset
                    value = struct.unpack_from('<I', self.raw, at)[0]
                    if low <= value < high:
                        struct.pack_into('<I', raw, at, value+delta)

    def test_validated_graph_at_different_load_base(self):
        # Rebase the validated subgraph, including absolute jump-table entries.
        # The packed PE relocation directory alone does not relocate unpacked
        # .text; this is a synthetic graph test, not a reconstructed live image.
        graph = self.collected_graph()
        raw, delta = bytearray(self.raw), 0x10000
        self.translate_operands(raw, graph, self.base, self.base+len(raw), delta)
        for table in graph.tables:
            for i in range(7):
                at = table-self.base+i*4
                struct.pack_into('<I', raw, at, struct.unpack_from('<I', raw, at)[0]+delta)
        image = Image(lambda p, n: bytes(raw[p:p+n]), self.base+delta, 'synthetic graph rebase')
        report = Discovery(image).run()
        self.assertEqual(report['status'], 'discovered', report)
        self.assertEqual(report['matches'][0]['initializer']['rva'], self.found['initializer']['rva'])

    def test_globals_moved_to_different_rva(self):
        graph, raw, delta = self.collected_graph(), bytearray(self.raw), 0x200
        old = int(self.found['pool_globals'][0]['head']['va'], 16)
        self.translate_operands(raw, graph, old, old+48, delta)
        at = old-self.base
        raw[at+delta:at+delta+48] = raw[at:at+48]
        raw[at:at+48] = bytes(48)
        report = self.run_image(raw)
        self.assertEqual(report['status'], 'discovered', report)
        self.assertEqual(report['matches'][0]['pool_globals'][0]['head']['rva'], hex(at+delta))

    def test_selector_one_retargeted(self):
        graph, raw = self.collected_graph(), bytearray(self.raw)
        self.assertEqual(len(graph.tables), 1)
        at = next(iter(graph.tables))-self.base
        raw[at+4:at+8] = raw[at:at+4]
        self.reject(raw, 'dispatcher')

    def test_no_candidate_and_wrong_import_name(self):
        raw = bytearray(self.raw)
        raw[self.rva('initializer'):self.rva('query_return')+214] = bytes(253)
        self.reject(raw, 'no fully validated')
        raw = bytearray(self.raw)
        at = raw.index(b'GlobalMemoryStatus\0')
        raw[at] = ord('X')
        with self.assertRaisesRegex(Refused, 'import missing'):
            self.run_image(raw)

    def test_retired_cap_rejected(self):
        raw = bytearray(self.raw)
        for operand in self.found["cap_operands"]:
            struct.pack_into("<I", raw, int(operand["rva"], 16), 448)
        self.set_pools(raw, 384)
        self.reject(raw, "unsupported cap")

    def test_cap_pair_and_layout(self):
        raw = bytearray(self.raw)
        at = [int(p['rva'], 16) for p in self.found['cap_operands']]
        struct.pack_into('<I', raw, at[0], 384)
        self.reject(raw, 'cap')
        struct.pack_into('<I', raw, at[1], 384)
        self.reject(raw, 'cap/layout')
        self.set_pools(raw, 320)
        self.assertEqual(self.run_image(raw)['status'], 'discovered')
        self.set_pools(raw, 64)
        self.assertEqual(self.run_image(raw)['status'], 'discovered')
        for p in at:
            struct.pack_into('<I', raw, p, 512)
        self.reject(raw, 'unsupported cap')

    def test_uninitialized_and_partial_globals(self):
        raw = bytearray(self.raw)
        g = int(self.found['pool_globals'][0]['head']['rva'], 16)
        raw[g:g+40] = bytes(40)
        self.assertEqual(self.run_image(raw)['status'], 'discovered')
        struct.pack_into('<I', raw, g, 0x10000000)
        self.reject(raw)

    def test_each_pool_global_reference(self):
        for wrapper in self.found['wrappers']:
            raw = bytearray(self.raw)
            d = Discovery(self.image(raw))
            ins = d.decode(int(wrapper['va'], 16))[3]  # push derived head address
            struct.pack_into('<I', raw, ins.address-self.base+ins.imm_offset, 0x1234)
            self.reject(raw)

    def test_every_initializer_branch(self):
        d = Discovery(self.image(self.raw))
        start = self.rva('initializer')
        instructions = d.decode(self.base+start)
        end = self.rva('query_return') + 214
        for ins in instructions:
            if ins.address >= self.base+end:
                break
            if ins.mnemonic.startswith('j'):
                raw = bytearray(self.raw)
                raw[ins.address-self.base+ins.imm_offset] ^= 1
                self.reject(raw, 'branch target')

    def test_builder_allocator_and_size_helper_tamper(self):
        for key in ('builder', 'reverse_allocator', 'size_helper', 'backing_wrapper', 'backing_retry'):
            raw = bytearray(self.raw)
            raw[self.rva(key)] = 0xcc
            self.reject(raw)

    def test_mixed_globals(self):
        raw = bytearray(self.raw)
        g = int(self.found['pool_globals'][0]['head']['rva'], 16)
        struct.pack_into('<I', raw, g+4, pools(64)[0][1])
        self.reject(raw)

    def moved_initializer(self, raw, keep_original=False):
        d = Discovery(self.image(raw))
        old, new = self.rva('initializer'), self.rva('initializer')+0x10000
        end = self.rva('query_return')+214
        code = bytearray(raw[old:end])
        for ins in d.decode(self.base+old):
            if ins.address >= self.base+end:
                break
            if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
                # Calls leave this function. Internal branches move with it.
                pos = ins.address-self.base-old+ins.imm_offset
                self.assertEqual(ins.imm_size, 4)
                displacement = struct.unpack_from('<i', code, pos)[0]
                struct.pack_into('<i', code, pos, displacement-(new-old))
        raw[new:new+len(code)] = code
        if not keep_original:
            raw[old:end] = b'\x90'*(end-old)
        return new

    def test_initializer_relocated_to_new_rva(self):
        raw = bytearray(self.raw)
        new = self.moved_initializer(raw)
        report = self.run_image(raw)
        self.assertEqual(report['status'], 'discovered', report)
        self.assertEqual(report['matches'][0]['initializer']['rva'], hex(new))

    def test_duplicate_valid_initializer_refused(self):
        raw = bytearray(self.raw)
        self.moved_initializer(raw, keep_original=True)
        report = self.run_image(raw)
        self.assertEqual(report['status'], 'refused')
        self.assertEqual(report['validated_count'], 2)
        self.assertIn('ambiguous', report['reason'])

    def test_missing_executable_read_refused(self):
        image = self.image(self.raw)
        original = image.reader
        def read(p, n):
            if p == next(section['rva'] for section in image.sections if section['flags'] & 0x20000000):
                raise Refused('simulated missing code page')
            return original(p, n)
        image.reader = read
        with self.assertRaisesRegex(Refused, 'missing code'):
            Discovery(image)

    def test_changed_read_refused(self):
        image = self.image(self.raw)
        original, reads = image.reader, {}
        g = int(self.found['pool_globals'][0]['head']['rva'], 16)
        def read(p, n):
            result = original(p, n)
            if (p, n) == (g, 40):
                reads[p] = reads.get(p, 0)+1
                if reads[p] > 1:
                    return bytes(40)
            return result
        image.reader = read
        with self.assertRaisesRegex(Refused, 'changed'):
            Discovery(image).run()


@unittest.skipUnless(os.environ.get('LIMITBREAK_TEST_DUMP'), 'set LIMITBREAK_TEST_DUMP for dump reader integration')
class DumpIntegrationTests(unittest.TestCase):
    def test_existing_dump(self):
        owner = DumpImage(os.environ['LIMITBREAK_TEST_DUMP'])
        try:
            report = Discovery(owner.image).run()
            self.assertEqual(report['status'], 'discovered', report)
            self.assertEqual(report['validated_count'], 1)
            result = report['matches'][0]
            self.assertEqual(len(result['pool_globals']), 5)
            self.assertIn('complete layout', result['layout'])
        finally:
            owner.close()


if __name__ == '__main__':
    unittest.main()
