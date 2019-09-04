#!/usr/bin/env python
import unittest
import os
import sys

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.dirname(script_dir))
from snort2fortigate import test_convert

class TestSnort2Fortigate(unittest.TestCase):
		
    def testConvert(self):	
        ifh = open(os.path.join(script_dir, 'snort_custom.rules'), 'r')
        assertfh = open(os.path.join(script_dir, 'assert_fgt.rules'), 'r')
        in_f = ifh.read().splitlines()
        assert_f = assertfh.read().splitlines()
        for i, rule in enumerate(in_f):
            result = test_convert(rule)
            self.assertEqual(result[1].rstrip(), assert_f[i].rstrip())

if __name__ == '__main__':
    unittest.main()