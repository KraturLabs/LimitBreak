import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import struct
import unittest
from occupancy import observe, Rejected


class WalkTests(unittest.TestCase):
    def setUp(self):
        self.head=0x20000000
        self.end=self.head+192*1048576-144
        self.middle=self.head+0x1000
        self.data={
            self.head:[0,0,self.middle,0,self.end,0],
            self.middle:[0,1,self.end,self.head,0xdeadbeef,0xdeadbeef],
            self.end:[0,1,0,self.middle,0,self.head]}

    def read(self,a,n):
        return struct.pack('<6I',*self.data[a])[:n]

    def run_observation(self,**kw):
        return observe(self.read,self.head,self.end,**kw)

    def test_accounting_and_stale_allocated_links(self):
        r=self.run_observation()
        self.assertEqual(r['free_payload_bytes'],4096-32)
        self.assertEqual(r['block_headers_bytes'],64)
        self.assertEqual(r['span_bytes'],r['free_payload_bytes']+r['occupied_payload_bytes']+64)

    def test_bad_physical_link(self):
        self.data[self.middle][3]=0
        with self.assertRaises(Rejected):self.run_observation()

    def test_bad_free_link(self):
        self.data[self.end][5]=self.middle
        with self.assertRaises(Rejected):self.run_observation()

    def test_outside_pool(self):
        self.data[self.head][2]=self.end+16
        with self.assertRaises(Rejected):self.run_observation()

    def test_unknown_flag(self):
        self.data[self.head][1]=2
        with self.assertRaises(Rejected):self.run_observation()

    def test_short_read(self):
        with self.assertRaises(Rejected):observe(lambda a,n:b'',self.head,self.end)

    def test_budgets(self):
        with self.assertRaises(Rejected):self.run_observation(max_nodes=1)
        with self.assertRaises(Rejected):self.run_observation(budget_s=0)

    def test_changed_second_walk(self):
        calls=0
        def read(a,n):
            nonlocal calls
            calls+=1
            if calls==4:self.data[self.head][1]=1
            return self.read(a,n)
        with self.assertRaises(Rejected):observe(read,self.head,self.end)

    def test_exhaustion_not_zero_failure(self):
        self.data[self.head][1]=1
        r=self.run_observation()
        self.assertEqual(r['free_payload_bytes'],0)
        self.assertIsNone(r['free_fragmentation_ratio'])

    def test_320_capacity(self):
        old=self.end
        self.end=self.head+320*1048576-144
        self.data[self.end]=self.data.pop(old)
        self.data[self.head][4]=self.end
        self.data[self.middle][2]=self.end
        self.assertEqual(self.run_observation()['span_bytes'],320*1048576-144)


if __name__=='__main__':unittest.main()
