#!/usr/bin/python

import sys

from distutils.version import StrictVersion

# read the two git diff lines about version
two_lines = sys.stdin.read()
if 'version' not in two_lines:
    sys.exit("version not found in args. Build FAILED")
lines = str(two_lines).split('\n')
version1 = StrictVersion(lines[0].split('=')[1].strip())
version2 = StrictVersion(lines[1].split('=')[1].strip())
print 'version1: ', version1
print 'version2: ', version2
if version2 > version1:
    print 'Version update correct.'
else:
    sys.exit("new version string is < old version string. Build FAILED")
