"""Read-only invariants for the five supported resource arenas."""

class BoundaryWatcher:
    def __init__(self):
        self.baseline = None

    def check(self, snapshot):
        pools = snapshot['pools']
        capacity = snapshot['pool_capacity_mib']
        expected = [capacity * 1048576 - 144, 10 * 1048576 - 144,
                    16 * 1048576 - 144, 4096 - 144, 4096 - 144]
        issues = []
        if capacity not in (192, 320) or len(pools) != 5:
            return ['unsupported_pool_layout']
        bounds = tuple((p['head'], p['end']) for p in pools)
        for i, ((head, end), span) in enumerate(zip(bounds, expected)):
            if head < 0x10000 or end + 32 > 0x100000000 or head % 16 or end % 16 or end-head != span:
                issues.append(f'pool_{i}_invalid_bounds')
            cursor = head
            for region in sorted(snapshot['backing_regions'], key=lambda r: r['base']):
                if region['base'] <= cursor < region['base'] + region['size']:
                    if region['state'] != 0x1000 or region['protect'] != 4 or region['type'] != 0x20000:
                        issues.append(f'pool_{i}_backing_not_private_readwrite_committed')
                    cursor = min(end+32, region['base']+region['size'])
                if cursor == end+32:
                    break
            if cursor != end+32:
                issues.append(f'pool_{i}_backing_gap')
        ordered = sorted(bounds)
        if any(left[1]+32 > right[0] for left, right in zip(ordered, ordered[1:])):
            issues.append('pool_overlap_including_sentinel')
        if any(bounds[left][1]+144 != bounds[right][0] for left,right in ((0,1),(1,3),(3,2),(2,4))):
            issues.append('unexpected_sibling_layout')
        if self.baseline is not None and bounds != self.baseline:
            issues.append('pool_boundaries_moved')
        if self.baseline is None and not issues:
            self.baseline = bounds
        return issues
