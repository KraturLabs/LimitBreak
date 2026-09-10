"""Read-only, bounded FFXiMain resource-memory discovery. Never patches a client."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deps' / 'discovery'))
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    raise SystemExit('Install capstone==5.0.9 into deps/discovery; see docs/DISCOVERY.md')
from discovery_image import Image, Refused, require, file_image, DumpImage, LiveImage
import discovery_rules as rules


def schema(text):
    rows, labels = [], {}
    for line in text.strip().splitlines():
        line = line.strip()
        if ': ' in line:
            label, line = line.split(': ', 1)
            labels[label] = len(rows)
        rows.append(line)
    return rows, labels


class Discovery:
    def __init__(self, image):
        self.image = image
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.code = image.code_sections()  # Missing executable pages fail closed.
        self.imports = image.imports()

    def decode(self, address, budget=1024):
        rva = self.image.va(address, executable=True)
        section = self.image.section(rva)
        data = self.image.read(rva, min(budget, section['rva'] + section['size'] - rva))
        return list(self.md.disasm(data, address))

    def match(self, address, text, bindings=None):
        rows, label_indices = schema(text)
        instructions = self.decode(address)[:len(rows)]
        require(len(instructions) == len(rows), 'short/undecodable function')
        labels = {k: instructions[v].address for k, v in label_indices.items()}
        values = dict(bindings or {})
        for expected, ins in zip(rows, instructions):
            actual = (ins.mnemonic + ' ' + ins.op_str).strip()
            tokens = list(re.finditer(r'[$@](\w+)', expected))
            pattern, end = '', 0
            for token in tokens:
                pattern += re.escape(expected[end:token.start()]) + r'(0x[0-9a-f]+|[0-9]+)'
                end = token.end()
            pattern += re.escape(expected[end:])
            result = re.fullmatch(pattern, actual)
            require(result is not None, f'semantic mismatch at RVA {ins.address-self.image.base:#x}: expected {expected}')
            for token, raw in zip(tokens, result.groups()):
                key, value = token.group(1), int(raw, 0)
                if token.group(0)[0] == '@':
                    require(labels[key] == value, 'branch target relationship mismatch: ' + key)
                else:
                    require(key not in values or values[key] == value, 'operand relationship mismatch: ' + key)
                    values[key] = value
        return values, labels, instructions

    def search(self, needle):
        hits = []
        for rva, data in self.code:
            at = data.find(needle)
            while at >= 0:
                hits.append(self.image.base + rva + at)
                require(len(hits) <= 256, 'candidate budget exceeded')
                at = data.find(needle, at + 1)
        return hits

    def location(self, address):
        return {'va': hex(address), 'rva': hex(address - self.image.base)}

    def validate(self, address, memory_iat):
        passed = []
        v, labels, ins = self.match(address, rules.INITIALIZER, {'memory_iat': memory_iat})
        require(v['cap'] in (256, 384), 'unsupported cap pair (only stock 256 or observed patched 384)')
        passed.append('complete initializer semantics, internal branches, equal caps, 64 MiB retry and five construction calls')
        cap_operands = []
        for name in ('cap_compare', 'cap_store'):
            i = next(i for i in ins if i.address == labels[name])
            require(i.imm_size == 4 and i.imm_offset > 0, 'cap is not an imm32 operand')
            at = i.address + i.imm_offset
            require(self.image.u32(at-self.image.base) == v['cap'], 'cap operand decoding mismatch')
            cap_operands.append(self.location(at))
        globals_, builder = [], None
        for index in range(5):
            w, _, _ = self.match(v[f'pool{index}'], rules.POOL_WRAPPER)
            require(w['end'] == w['head'] + 4 and w['head'] % 4 == 0, 'invalid pool head/end pair')
            self.image.va(w['head'], 8, writable=True)
            require(builder is None or builder == w['builder'], 'builders do not converge')
            builder = w['builder']
            globals_.append(w['head'])
        require(len({v[f'pool{i}'] for i in range(5)}) == 5, 'aliased construction wrappers')
        require(globals_ == [globals_[0] + i * 8 for i in range(5)], 'five globals not distinct contiguous table slots')
        self.match(builder, rules.BUILDER)
        passed.append('five distinct wrappers converge on validated aligned 32-byte-header/sentinel builder; physical order 0,1,3,2,4')

        # Derive allocator from references to the discovered resource globals,
        # not from a fixed function offset or a nearby-address guess.
        route_hits = self.search(b'\x8b\x0d' + struct.pack('<I', globals_[0]+4)
                                 + b'\x8b\x15' + struct.pack('<I', globals_[0]))
        routes, route_errors = [], []
        for route in route_hits:
            try:
                r, _, _ = self.match(route, rules.RESOURCE_ROUTE,
                                     {'head': globals_[0], 'end': globals_[0]+4})
                a, _, _ = self.match(r['reverse'], rules.REVERSE)
                self.match(a['size_helper'], rules.SIZE_HELPER)
                require(a['request'] == globals_[0]+40 and a['tag'] == globals_[0]+44,
                        'allocator scratch/tag globals do not follow pool table')
                self.image.va(a['request'], 8, writable=True)
                self.image.va(r['vtable'], 4)
                self.image.va(r['route_failure'], executable=True)
                # The route must really be selector 1 of the request dispatcher.
                dispatchers = []
                needle = b'\x8b\x44\x24\x04\x8b\x15' + struct.pack('<I', a['request'])
                for dispatch in self.search(needle):
                    try:
                        d, _, _ = self.match(dispatch, rules.DISPATCH, {'request': a['request']})
                        table = self.image.va(d['table'], 28)
                        entries = struct.unpack('<7I', self.image.read(table, 28))
                        require(entries[1] == route, 'selector 1 does not target resource reverse route')
                        for target in (*entries, d['default']):
                            self.image.va(target, executable=True)
                        dispatchers.append(dispatch)
                    except Refused:
                        continue
                require(len(dispatchers) == 1, 'resource dispatcher missing or ambiguous')
                routes.append((route, r, a, dispatchers[0]))
            except Refused as error:
                route_errors.append(str(error))
                continue
        require(len(routes) == 1, 'resource reverse allocation relationship missing, unsupported or ambiguous: '
                + '; '.join(route_errors[:6]))
        route, r, a, dispatch = routes[0]
        passed.append('unique selector-1 resource route, reverse free-list/splitting/null-return semantics and payload-size helper')

        b, _, _ = self.match(v['backing'], rules.BACKING)
        retry, _, _ = self.match(b['retry'], rules.RETRY)
        self.image.va(retry['new_handler'], executable=True)
        heap_iat = self.imports.get(('kernel32.dll', 'HeapAlloc'))
        require(heap_iat is not None, 'HeapAlloc import unavailable')
        adapter = self.decode(retry['heap_adapter'], 512)
        self.match(retry['heap_adapter'], rules.ADAPTER_PREFIX)
        epilogues = [i for i in range(len(adapter)-1)
                     if adapter[i].mnemonic == 'leave' and adapter[i+1].mnemonic == 'ret']
        require(epilogues, 'backing adapter epilogue unavailable')
        adapter = adapter[:epilogues[0]+2]
        for instruction in adapter:
            if instruction.mnemonic.startswith('j'):
                require(instruction.op_str.startswith('0x') and
                        adapter[0].address <= int(instruction.op_str, 16) <= adapter[-1].address,
                        'backing adapter branch leaves bounded function')
        # A bounded relationship check of the CRT tail, not a full CRT audit.
        heap_calls = [i for i in adapter if i.mnemonic == 'call'
                      and i.op_str == f'dword ptr [{heap_iat:#x}]']
        require(len(heap_calls) == 1, 'unique HeapAlloc tail missing in backing adapter')
        tail = rules.HEAP_TAIL
        idx = adapter.index(heap_calls[0])
        require(idx >= 2, 'truncated HeapAlloc arguments')
        tail_values, _, _ = self.match(adapter[idx-2].address, tail, {'heap_iat': heap_iat})
        self.image.va(tail_values['heap_handle'], 4, writable=True)
        passed.append('same backing wrapper on initial/retry paths; CRT allocation retry and HeapAlloc tail linked')

        data = self.image.read(globals_[0]-self.image.base, 40)
        pairs = list(struct.iter_unpack('<II', data))
        layout = validate_layout(pairs, v['cap'])
        passed.append('pool globals: ' + layout)
        return {
            'initializer': self.location(address), 'query_return': self.location(labels['query_return']),
            'cap_operands': cap_operands, 'cap_mib': v['cap'],
            'pool_globals': [dict(head=self.location(g), end=self.location(g+4)) for g in globals_],
            'pool_bounds': [{'head': hex(h), 'end': hex(e)} for h, e in pairs],
            'layout': layout, 'builder': self.location(builder),
            'wrappers': [self.location(v[f'pool{i}']) for i in range(5)],
            'resource_dispatcher': self.location(dispatch), 'resource_route': self.location(route),
            'reverse_allocator': self.location(r['reverse']), 'size_helper': self.location(a['size_helper']),
            'backing_wrapper': self.location(v['backing']), 'backing_retry': self.location(b['retry']),
            'heap_adapter': self.location(retry['heap_adapter']),
            'memory_status_iat': self.location(memory_iat), 'heap_alloc_iat': self.location(heap_iat),
            'passed': passed,
            'diagnostic_initializer_sha256': hashlib.sha256(self.image.read(address-self.image.base,
                  ins[-1].address + ins[-1].size-address)).hexdigest(),
        }

    def run(self):
        memory = self.imports.get(('kernel32.dll', 'GlobalMemoryStatus'))
        require(memory is not None, 'GlobalMemoryStatus named import missing')
        calls = self.search(b'\xff\x15' + struct.pack('<I', memory))
        candidates = set()
        for call in calls:
            # Search bounded preceding prologues; no per-client RVA or fixed
            # distance from another discovered function is used.
            for rva, data in self.code:
                relative = call-self.image.base-rva
                if 0 <= relative < len(data):
                    for at in range(max(0, relative-64), relative):
                        if data[at:at+3] == b'\x83\xec\x20':
                            candidates.add(self.image.base+rva+at)
        require(len(candidates) <= 64, 'initializer candidate budget exceeded')
        valid, rejected = [], []
        for address in sorted(candidates):
            try:
                valid.append(self.validate(address, memory))
            except Refused as error:
                rejected.append({'candidate': self.location(address), 'reason': str(error)})
        report = {'status': 'discovered' if len(valid) == 1 else 'refused',
                  'source': self.image.source, 'base': hex(self.image.base),
                  'candidate_count': len(candidates), 'validated_count': len(valid),
                  'rejected_candidates': rejected, 'matches': valid,
                  'evidence': getattr(self.image, 'evidence', {}),
                  'limitations': ['read-only discovery, not patch eligibility or runtime compatibility',
                                 'CRT tail relationship checked; full CRT/free/forward allocator not audited',
                                 'matching sequential reads cannot exclude concurrent ABA changes']}
        if len(valid) != 1:
            report['reason'] = 'ambiguous validated initializers' if valid else 'no fully validated initializer'
        # Detect visible changes to all ranges used for discovery, including
        # candidate scan coverage. A read failure refuses rather than guessing.
        for (rva, size), before in list(self.image.observed.items()):
            require(self.image.read(rva, size) == before, 'image changed during discovery')
        for offset, before in self.image.header_observed:
            require(self.image.reader(offset, len(before)) == before, 'PE headers changed during discovery')
        return report


def validate_layout(pools, cap):
    require(len(pools) == 5 and cap in (256, 384), 'unsupported pool count or cap')
    if all(h == 0 and e == 0 for h, e in pools):
        return 'uninitialized (structure found; patch timing not established)'
    first = pools[0][1]-pools[0][0]
    choices = {n*1048576-144: n for n in (64, 192, 320)}
    require(first in choices, 'unexpected resource pool span')
    capacity = choices[first]
    require((cap == 256 and capacity in (64, 192)) or (cap == 384 and capacity in (64, 320)),
            'cap/layout disagreement')
    budgets = [capacity*1048576, 10*1048576, 16*1048576, 4096, 4096]
    for (head, end), budget in zip(pools, budgets):
        require(0x10000 <= head < end and end + 32 <= 0x100000000
                and head % 16 == end % 16 == 0 and end-head == budget-144,
                'malformed pool bounds/span/alignment')
    order = [0, 1, 3, 2, 4]
    require(all(pools[x][1]+144 == pools[y][0] for x, y in zip(order, order[1:])),
            'mixed/overlapping pool layout or incorrect sibling order')
    return f'{capacity} MiB complete layout (observation only)'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capture', type=Path, help='existing mapped FFXiMain image')
    group.add_argument('--file', type=Path, help='on-disk PE; packed code is refused')
    group.add_argument('--dump', type=Path, help='existing Memory64 minidump; read FFXiMain only')
    group.add_argument('--pid', type=int, help='already running client; never launches it')
    parser.add_argument('--base', type=lambda x: int(x, 0), help='required loaded base for --capture')
    args = parser.parse_args()
    if bool(args.capture) != (args.base is not None):
        parser.error('--base is required only with --capture')
    owner, image = None, None
    try:
        if args.dump:
            owner = DumpImage(args.dump)
            image = owner.image
        elif args.pid is not None:
            owner = LiveImage(args.pid)
            image = owner.image
        else:
            image = file_image(args.capture or args.file, args.base)
        report = Discovery(image).run()
    except (Refused, OSError, UnicodeError, struct.error) as error:
        report = {'status': 'refused', 'reason': str(error)}
        if image is not None:
            report.update(source=image.source, evidence=getattr(image, 'evidence', {}))
    finally:
        if owner:
            owner.close()
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'discovered' else 2


if __name__ == '__main__':
    sys.exit(main())
