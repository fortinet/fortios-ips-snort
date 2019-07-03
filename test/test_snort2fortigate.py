#!/usr/bin/env python
import unittest
import os
import sys
from StringIO import StringIO

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.dirname(script_dir))
from snort2fortigate import convert

class TestSnort2Fortigate(unittest.TestCase):

    def testConvert(self):
        ifh = open(os.path.join(script_dir, 'example.rule.txt'), 'r')
        ofh = StringIO()
        convert(ifh, ofh)
        self.assertEqual(ofh.getvalue(), 'F-SBID( --name "SID1000001-ICMP.Testing.Rule"; --protocol icmp; )\n')

if __name__ == '__main__':
    unittest.main()
