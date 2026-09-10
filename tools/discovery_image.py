"""Bounded PE32 readers. No injection, execution, target writes or dump creation."""
import bisect
import ctypes as C
from ctypes import wintypes as W
import hashlib
import mmap
from pathlib import Path
import struct


class Refused(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


class Image:
    def __init__(self, read, base, source, disk=False):
        self.reader, self.base, self.source, self.disk = read, base, source, disk
        self.observed = {}
        self.header_observed = []
        def read(offset, size):
            data = self.reader(offset, size)
            require(len(data) == size, 'short PE header read')
            self.header_observed.append((offset, data))
            return data
        head = read(0, 64)
        require(head[:2] == b'MZ', 'missing DOS signature')
        pe = struct.unpack_from('<I', head, 60)[0]
        require(64 <= pe <= 4096, 'PE header offset outside budget')
        h = read(pe, 24)
        require(h[:4] == b'PE\0\0' and struct.unpack_from('<H', h, 4)[0] == 0x14c,
                'expected x86 PE')
        count, optional = struct.unpack_from('<H', h, 6)[0], struct.unpack_from('<H', h, 20)[0]
        require(1 <= count <= 32 and optional == 224, 'unsupported PE section/header count')
        opt = read(pe + 24, optional)
        require(struct.unpack_from('<H', opt)[0] == 0x10b, 'expected PE32')
        self.size = struct.unpack_from('<I', opt, 56)[0]
        self.header_size = struct.unpack_from('<I', opt, 60)[0]
        require(4096 <= self.size <= 64 * 1048576, 'image size outside 64 MiB budget')
        require(0 < self.header_size <= self.size, 'invalid header size')
        if disk:
            self.base = struct.unpack_from('<I', opt, 28)[0]
        require(0x10000 <= self.base and self.base + self.size <= 0x100000000,
                'invalid x86 image base')
        self.import_rva, self.import_size = struct.unpack_from('<II', opt, 104)
        self.sections = []
        for i in range(count):
            raw = read(pe + 24 + optional + i * 40, 40)
            vs, rva, length, offset = struct.unpack_from('<IIII', raw, 8)
            section = dict(name=raw[:8].rstrip(b'\0').decode('ascii', errors='replace'),
                           rva=rva, size=vs, raw_size=length, offset=offset,
                           flags=struct.unpack_from('<I', raw, 36)[0])
            require(vs > 0 and rva >= self.header_size and rva + vs <= self.size,
                    'invalid section bounds')
            require(all(rva + vs <= s['rva'] or s['rva'] + s['size'] <= rva
                        for s in self.sections), 'overlapping PE sections')
            self.sections.append(section)

    def section(self, rva, size=1):
        return next((s for s in self.sections
                     if s['rva'] <= rva and rva + size <= s['rva'] + s['size']), None)

    def read(self, rva, size):
        require(0 <= rva and 0 <= size <= self.size and rva + size <= self.size,
                'read outside image')
        offset = rva
        if self.disk:
            if rva >= self.header_size:
                s = self.section(rva, size)
                require(s is not None and rva + size <= s['rva'] + s['raw_size'],
                        'packed/unbacked code or data: loaded image required')
                offset = s['offset'] + rva - s['rva']
            else:
                require(rva + size <= self.header_size, 'read crosses headers')
        result = self.reader(offset, size)
        require(len(result) == size, 'short image read')
        self.observed.setdefault((rva, size), result)
        return result

    def va(self, address, size=1, executable=False, writable=False):
        rva = address - self.base
        s = self.section(rva, size)
        require(s is not None, 'derived address outside a section')
        if executable:
            require(bool(s['flags'] & 0x20000000), 'derived code target not executable')
        if writable:
            require(bool(s['flags'] & 0x80000000) and not s['flags'] & 0x20000000,
                    'pool globals must be writable non-executable data')
        return rva

    def u32(self, rva):
        return struct.unpack('<I', self.read(rva, 4))[0]

    def string(self, rva):
        out = bytearray()
        for i in range(256):
            b = self.read(rva + i, 1)
            if b == b'\0':
                return out.decode('ascii')
            out += b
        raise Refused('unterminated import name')

    def imports(self):
        require(20 <= self.import_size <= 65536, 'missing or unsupported import directory')
        found = {}
        for i in range(min(self.import_size // 20, 256)):
            lookup, _, _, name, iat = struct.unpack('<5I', self.read(self.import_rva + i * 20, 20))
            if not any((lookup, name, iat)):
                return found
            require(lookup and name and iat, 'original import names unavailable')
            dll = self.string(name).lower()
            for j in range(4096):
                entry = self.u32(lookup + j * 4)
                if not entry:
                    break
                if entry & 0x80000000:
                    continue
                key = (dll, self.string(entry + 2))
                require(key not in found, 'duplicate named import')
                self.va(self.base + iat + j * 4, 4)
                found[key] = self.base + iat + j * 4
            else:
                raise Refused('import thunk budget exceeded')
        raise Refused('unterminated import descriptors')

    def code_sections(self):
        result = []
        for s in self.sections:
            if s['flags'] & 0x20000000:
                result.append((s['rva'], self.read(s['rva'], s['size'])))
        require(result, 'no executable sections')
        return result


def file_image(path, base=None):
    path = Path(path)
    require(path.stat().st_size <= 64 * 1048576, 'capture/file exceeds 64 MiB')
    raw = path.read_bytes()
    def read(offset, size):
        require(0 <= offset and offset + size <= len(raw), 'truncated file/capture')
        return raw[offset:offset + size]
    image = Image(read, base, str(path.resolve()), disk=base is None)
    image.evidence = {'input_sha256': hashlib.sha256(raw).hexdigest()}
    return image


class DumpImage:
    """Only FFXiMain ranges are read from an existing full minidump."""
    def __init__(self, path):
        self.file = open(path, 'rb')
        self.mapping = None
        try:
            require(self.file.seek(0, 2) >= 32, 'truncated minidump header')
            self.mapping = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
            d = self.mapping
            def part(at, n):
                require(0 <= at and at + n <= len(d), 'truncated minidump')
                return d[at:at + n]
            require(part(0, 4) == b'MDMP', 'not a minidump')
            count, directory = struct.unpack('<II', part(8, 8))
            require(count <= 128, 'minidump stream budget exceeded')
            streams = {}
            for i in range(count):
                typ, size, rva = struct.unpack('<III', part(directory + i * 12, 12))
                if typ == 0 and size == 0 and rva == 0:
                    continue  # MINIDUMP_DIRECTORY padding / UnusedStream.
                require(typ not in streams, 'duplicate minidump stream')
                streams[typ] = (rva, size)
            require(4 in streams and 9 in streams, 'module and Memory64 streams required')
            r, size = streams[4]
            n = struct.unpack('<I', part(r, 4))[0]
            require(n <= 2048 and 4 + n * 108 <= size, 'invalid module count')
            modules = []
            for i in range(n):
                base, length, _, _, name = struct.unpack('<QIIII', part(r + 4 + i * 108, 24))
                chars = struct.unpack('<I', part(name, 4))[0]
                require(chars <= 65536, 'module name too long')
                module = part(name + 4, chars).decode('utf-16-le')
                if module.replace('\\', '/').split('/')[-1].lower() == 'ffximain.dll':
                    modules.append((base, length, module))
            require(len(modules) == 1, 'expected exactly one FFXiMain module')
            base, length, module = modules[0]
            r, size = streams[9]
            n, at = struct.unpack('<QQ', part(r, 16))
            require(n <= 100000 and 16 + 16 * n <= size, 'invalid memory-range count')
            ranges = []
            for i in range(n):
                lo, amount = struct.unpack('<QQ', part(r + 16 + i * 16, 16))
                require(amount and at + amount <= len(d), 'invalid dump memory range')
                ranges.append((lo, lo + amount, at))
                at += amount
            ranges.sort()
            require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'overlapping dump ranges')
            starts = [x[0] for x in ranges]
            def read(offset, size):
                address, out = base + offset, bytearray()
                while size:
                    i = bisect.bisect_right(starts, address) - 1
                    require(i >= 0 and ranges[i][0] <= address < ranges[i][1], 'missing dump memory')
                    lo, hi, pos = ranges[i]
                    take = min(size, hi - address)
                    out += part(pos + address - lo, take)
                    address += take
                    size -= take
                return bytes(out)
            self.image = Image(read, base, str(Path(path).resolve()))
            require(self.image.size == length, 'dump module size mismatch')
            self.image.evidence = {'module_path': module, 'source': 'existing immutable dump'}
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.mapping is not None:
            self.mapping.close()
        self.file.close()


def bind(lib, name, args, result):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, result
    return fn


class LiveImage:
    def __init__(self, pid):
        require(C.sizeof(C.c_void_p) == 8, 'runtime reader requires 64-bit Windows Python')
        k, p = C.WinDLL('kernel32', use_last_error=True), C.WinDLL('psapi', use_last_error=True)
        self.close_handle = bind(k, 'CloseHandle', [W.HANDLE], W.BOOL)
        self.handle = bind(k, 'OpenProcess', [W.DWORD, W.BOOL, W.DWORD], W.HANDLE)(0x410, False, pid)
        require(self.handle, 'OpenProcess query/read denied: ' + str(C.get_last_error()))
        try:
            modules, needed = (C.c_void_p * 2048)(), W.DWORD()
            enum = bind(p, 'EnumProcessModulesEx', [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), W.DWORD], W.BOOL)
            require(enum(self.handle, modules, C.sizeof(modules), C.byref(needed), 1)
                    and needed.value <= C.sizeof(modules), 'module enumeration failed')
            name = bind(p, 'GetModuleFileNameExW', [W.HANDLE, C.c_void_p, W.LPWSTR, W.DWORD], W.DWORD)
            matches = []
            for m in modules[:needed.value // C.sizeof(C.c_void_p)]:
                buf = C.create_unicode_buffer(32768)
                count = name(self.handle, m, buf, len(buf))
                require(0 < count < len(buf), 'module path unavailable')
                if Path(buf.value).name.lower() == 'ffximain.dll':
                    matches.append((m, buf.value))
            require(len(matches) == 1, 'expected exactly one loaded FFXiMain.dll')
            base, path = matches[0]
            rpm = bind(k, 'ReadProcessMemory', [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)], W.BOOL)
            def read(offset, size):
                buf, done = C.create_string_buffer(size), C.c_size_t()
                require(rpm(self.handle, base + offset, buf, size, C.byref(done)) and done.value == size,
                        'unreadable runtime range at RVA ' + hex(offset))
                return buf.raw
            self.image = Image(read, base, path)
            self.image.evidence = {'pid': pid, 'module_path': path, 'access': 'query/read only'}
        except BaseException:
            self.close()
            raise

    def close(self):
        self.close_handle(self.handle)
