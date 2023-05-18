#!/usr/bin/env python3
import unittest
import os
import sys

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.dirname(script_dir))
from snort2fortigate import test_convert
from snort2fortigate import rule_maxlen

class TestSnort2Fortigate(unittest.TestCase):
		
    def testConvert(self):	
        with open(os.path.join(script_dir, 'snort_custom.rules'), 'r') as f:
              ifh = f.read()
              in_f = ifh.splitlines()
        with open(os.path.join(script_dir, 'assert_fgt.rules'), 'r') as f:
            assertfh = f.read()
            assert_f = assertfh.splitlines()

        for i, rule in enumerate(in_f):
            result = test_convert(rule, rule_maxlen)
            self.assertEqual(result[1].rstrip(), assert_f[i].rstrip())

class TestMantis(unittest.TestCase):
    maxDiff = None
    def testMaxLen(self):
        # Mantis 0705830
        with open(os.path.join(script_dir, 'max_len.rules'), 'r') as f:
              ifh = f.read()
              in_f = ifh.splitlines()
        with open(os.path.join(script_dir, 'assert_max_len.rules'), 'r') as f:
            assertfh = f.read()
            assert_f = assertfh.splitlines()

        for i, rule in enumerate(in_f):
            result = test_convert(rule, rule_maxlen)
            self.assertEqual(result[0], False)
            result = test_convert(rule, 4096)
            self.assertEqual(result[1].rstrip(), assert_f[i+1].rstrip())

    def testHTTPService(self):
        # Mantis 0745207
        with open(os.path.join(script_dir, 'http.rules'), 'r') as f:
              ifh = f.read()
              in_f = ifh.splitlines()
        with open(os.path.join(script_dir, 'assert_http.rules'), 'r') as f:
            assertfh = f.read()
            assert_f = assertfh.splitlines()

        for i, rule in enumerate(in_f):
            result = test_convert(rule, rule_maxlen)
            self.assertEqual(result[1].rstrip(), assert_f[i].rstrip())

    def testEscapeSlash(self):
        # Mantis 0693923
        with open(os.path.join(script_dir, 'escape.rules'), 'r') as f:
              ifh = f.read()
              in_f = ifh.splitlines()
        with open(os.path.join(script_dir, 'assert_escape.rules'), 'r') as f:
            assertfh = f.read()
            assert_f = assertfh.splitlines()

        for i, rule in enumerate(in_f):
            result = test_convert(rule, rule_maxlen)
            self.assertEqual(result[1].rstrip(), assert_f[i].rstrip())

if __name__ == '__main__':
    unittest.main()
