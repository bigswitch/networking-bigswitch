# Copyright 2014 Big Switch Networks, Inc.
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

import platform
from rhlib import BCFMode
from rhlib import get_bcf_mode
from send_lldp import send_lldp


def main():
    platform_os = platform.linux_distribution()[0]
    if "red hat" in platform_os.strip().lower():
        if BCFMode.MODE_P_V == get_bcf_mode():
            return
    send_lldp()


if __name__ == "__main__":
    main()
