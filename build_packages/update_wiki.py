import datetime
import requests
import sys

# read arguments
if len(sys.argv) != 3:
    sys.exit("Received incorrect number of arguments to script, 2 expected.")

page_id = sys.argv[1]
html_href = sys.argv[2]
print ("page_id is: %(page_id)s" % {'page_id': page_id})
print ("html_href is: %(html_href)s" % {'html_href': html_href})

headers = {'content-type': 'application/json'}
basic_auth = ('aditya.vaja@bigswitch.com', 'nSL2VSOHvaA7KmGIxRC53E0B')

# get newton existing page with body and version number
url = ('https://bigswitch.atlassian.net/wiki/rest/api/content/%(page_id)s?expand=body.storage,version' % {'page_id': page_id})
r = requests.get(url, headers=headers, auth=basic_auth)
json_out = r.json()
version_number = json_out['version']['number']
new_ver_num = version_number + 1

datetime_str = datetime.datetime.now().strftime("%B %d, %Y at %I:%M%p PST")
new_value = html_href + '<br/>' + datetime_str

# create new data to be uploaded
data = ('{"id":"%(page_id)s","body":{"storage":{"value": "%(new_value)s","representation":"storage"}},"version": {"number": %(new_ver_num)s},"type":"%(type)s","title":"%(title)s"}'
    % {'page_id': page_id,
    'new_value': new_value,
    'new_ver_num': new_ver_num,
    'type': json_out['type'],
    'title': json_out['title']})

p = requests.put(url, data=data, headers=headers, auth=basic_auth)
print p.json()
