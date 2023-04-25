#!/usr/bin/env python3
import unittest
import os
import sys

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.dirname(script_dir))
from snort2fortigate import test_convert

class TestSnort2Fortigate(unittest.TestCase):
		
    def testConvert(self):	
        with open(os.path.join(script_dir, 'snort_custom.rules'), 'r') as f:
              ifh = f.read()
              in_f = ifh.splitlines()
        with open(os.path.join(script_dir, 'assert_fgt.rules'), 'r') as f:
            assertfh = f.read()
            assert_f = assertfh.splitlines()

        for i, rule in enumerate(in_f):
            result = test_convert(rule)
            self.assertEqual(result[1].rstrip(), assert_f[i].rstrip())

if __name__ == '__main__':
    unittest.main()