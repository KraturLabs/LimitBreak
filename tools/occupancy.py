"""Read-only, bounded allocator observations. No engine calls or memory writes."""
import struct
import time


class Rejected(ValueError):
    pass


def observe(read, head, end, *, budget_s=0.25, max_nodes=65536):
    """Two matching walks are consistency evidence, NOT an atomic snapshot."""
    started = time.perf_counter()
    if head < 0x10000 or head % 16 or end % 16 or end <= head:
        raise Rejected('invalid bounds')
    if end - head not in (192 * 1048576 - 144, 320 * 1048576 - 144):
        raise Rejected('unsupported capacity')

    def header(address):
        if time.perf_counter() - started > budget_s:
            raise Rejected('time budget exceeded')
        if address < head or address > end or address % 16:
            raise Rejected('header outside pool or unaligned')
        raw = read(address, 24)
        if len(raw) != 24:
            raise Rejected('short header read')
        _, flag, nxt, prev, free_next, free_prev = struct.unpack('<6I', raw)
        if flag not in (0, 1):
            raise Rejected('unknown flag')
        return flag, nxt, prev, free_next, free_prev

    def walk():
        nodes, free = {}, set()
        address, previous = head, 0
        used_payload = free_payload = largest = 0
        while address != end:
            if len(nodes) >= max_nodes:
                raise Rejected('node budget exceeded')
            flag, nxt, prev, fn, fp = header(address)
            if prev != previous or nxt < address + 32 or nxt > end or nxt % 16:
                raise Rejected('physical chain inconsistent')
            payload = nxt - address - 32
            # Allocated blocks can retain stale free links: do not interpret them.
            nodes[address] = (flag, nxt, prev, fn if flag == 0 else None,
                              fp if flag == 0 else None)
            if flag == 0:
                free.add(address)
                free_payload += payload
                largest = max(largest, payload)
            else:
                used_payload += payload
            previous, address = address, nxt
        sentinel = header(end)
        if sentinel[:3] != (1, 0, previous) or sentinel[3] != 0:
            raise Rejected('end sentinel inconsistent')
        # The head also acts as the list anchor when occupied.
        seen, current, successor = set(), sentinel[4], end
        while current:
            if current in seen or current not in nodes:
                raise Rejected('free chain cycle or unknown node')
            flag, _, _, fn, fp = nodes[current]
            if flag != 0:
                if current != head:
                    raise Rejected('allocated node on free chain')
                break
            if fn != successor:
                raise Rejected('free links disagree')
            seen.add(current)
            successor, current = current, fp
        if seen != free:
            raise Rejected('physical and free lists disagree')
        return nodes, sentinel, used_payload, free_payload, largest

    first = walk()
    second = walk()
    if first != second:
        raise Rejected('allocator changed between walks')
    nodes, _, used, free, largest = second
    metadata = len(nodes) * 32
    if used + free + metadata != end - head:
        raise Rejected('accounting mismatch')
    return dict(status='consistent_observation_not_atomic', span_bytes=end-head,
                occupied_payload_bytes=used, free_payload_bytes=free,
                block_headers_bytes=metadata, largest_free_payload_bytes=largest,
                free_fragmentation_ratio=(1-largest/free) if free else None,
                nodes=len(nodes), duration_s=time.perf_counter()-started)
