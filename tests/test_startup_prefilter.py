"""Keep the hook's cheap return-site bytes synchronized with semantic discovery."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from discover import schema
from discovery_rules import INITIALIZER
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


class StartupPrefilterTests(unittest.TestCase):
    def test_production_prefilter_matches_initializer_query_return(self):
        source = (ROOT / 'src/plugin.cpp').read_text()
        startup = source.split('void DiscoverStartup(', 1)[1].split('void WINAPI MemoryQuery(', 1)[0]
        match = re.search(r'constexpr unsigned char prefix\[\]\{([^}]+)\}', startup)
        self.assertIsNotNone(match, 'update this regression check if the production prefilter moves')
        prefix = bytes(int(value.strip(), 0) for value in match[1].split(','))
        instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(prefix, 0x1000))
        self.assertEqual(len(instructions), 2, 'prefilter must contain both complete initializer instructions')
        self.assertEqual(sum(i.size for i in instructions), len(prefix))
        rows, labels = schema(INITIALIZER)
        at = labels['query_return']
        self.assertGreater(at, 0)
        self.assertEqual(rows[at - 1], 'call dword ptr [$memory_iat]')
        self.assertEqual([f'{i.mnemonic} {i.op_str}' for i in instructions], rows[at:at + 2])


if __name__ == '__main__':
    unittest.main()
