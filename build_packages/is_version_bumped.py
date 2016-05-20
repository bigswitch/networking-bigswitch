#!/usr/bin/python
# Copyright 2016 Big Switch Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import sys

from distutils.version import StrictVersion

# read the two git diff lines about version
two_lines = sys.stdin.read()
if 'version' not in two_lines:
    sys.exit("version not found in args. Build FAILED")
lines = str(two_lines).split('\n')
version1 = StrictVersion(lines[0].split('=')[1].strip())
version2 = StrictVersion(lines[1].split('=')[1].strip())
print ('version1: ', version1)
print ('version2: ', version2)
if version2 > version1:
    print ('Version update correct.')
else:
    sys.exit("new version string is < old version string. Build FAILED")
