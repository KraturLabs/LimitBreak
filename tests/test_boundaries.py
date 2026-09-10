"""Synthetic backing and five-pool validation; no process access."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from boundaries import BoundaryWatcher


def snapshot(capacity=320, head=0x20000000):
    budgets = [capacity * 1048576, 10 * 1048576, 16 * 1048576, 4096, 4096]
    pools = [None] * 5
    cursor = head
    for slot in (0, 1, 3, 2, 4):
        pools[slot] = dict(head=cursor, end=cursor + budgets[slot] - 144)
        cursor += budgets[slot]
    return dict(pool_capacity_mib=capacity, pools=pools, backing_regions=[
        dict(base=head, size=cursor-head, state=0x1000, protect=4, type=0x20000)])


class BoundaryTests(unittest.TestCase):
    def test_supported_layouts_and_stable_bounds(self):
        for capacity in (192, 320):
            watcher = BoundaryWatcher()
            self.assertEqual(watcher.check(snapshot(capacity)), [])
            self.assertEqual(watcher.check(snapshot(capacity)), [])
            self.assertIn('pool_boundaries_moved', watcher.check(snapshot(capacity, 0x30000000)))

    def test_backing_gap_or_wrong_protection(self):
        for field, value, issue in (('size', 16, 'pool_0_backing_gap'),
                                    ('protect', 2, 'pool_0_backing_not_private_readwrite_committed')):
            data = snapshot()
            data['backing_regions'][0][field] = value
            self.assertIn(issue, BoundaryWatcher().check(data))

    def test_invalid_layout_does_not_set_baseline(self):
        watcher = BoundaryWatcher()
        bad = snapshot()
        bad['pools'][4] = copy.deepcopy(bad['pools'][3])
        self.assertIn('unexpected_sibling_layout', watcher.check(bad))
        self.assertIsNone(watcher.baseline)
        self.assertEqual(watcher.check(snapshot()), [])

    def test_retired_capacity_rejected(self):
        self.assertEqual(BoundaryWatcher().check(snapshot(384)), ['unsupported_pool_layout'])


if __name__ == '__main__':
    unittest.main()
