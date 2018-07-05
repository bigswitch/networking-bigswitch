#!/usr/bin/python
# Copyright 2018 Big Switch Networks, Inc.
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

import datetime
import requests
import sys

# read arguments
if len(sys.argv) != 5:
    sys.exit("Received incorrect number of arguments to script, 4 expected.")

conf_user = sys.argv[1]
conf_token = sys.argv[2]
page_id = sys.argv[3]
html_href = sys.argv[4]
print ("page_id is: %(page_id)s" % {'page_id': page_id})
print ("html_href is: %(html_href)s" % {'html_href': html_href})
basic_auth = (conf_user, conf_token)
print ("basic_auth is %(auth)s" % {'auth': basic_auth})

headers = {'content-type': 'application/json'}

# get newton existing page with body and version number
url = ('https://bigswitch.atlassian.net/wiki/rest/api/content/%(page_id)s'
       '?expand=body.storage,version' % {'page_id': page_id})
r = requests.get(url, headers=headers, auth=basic_auth)
json_out = r.json()
version_number = json_out['version']['number']
new_ver_num = version_number + 1

datetime_str = datetime.datetime.now().strftime("%B %d, %Y at %I:%M%p PST")
new_value = html_href + '<br/>' + datetime_str

# create new data to be uploaded
data = ('{"id":"%(page_id)s",'
        '"body":{"storage":{"value": "%(new_value)s",'
        '"representation":"storage"}},'
        '"version": {"number": %(new_ver_num)s},'
        '"type":"%(type)s","title":"%(title)s"}'
        % {'page_id': page_id,
           'new_value': new_value,
           'new_ver_num': new_ver_num,
           'type': json_out['type'],
           'title': json_out['title']})

p = requests.put(url, data=data, headers=headers, auth=basic_auth)
print (p.json())
