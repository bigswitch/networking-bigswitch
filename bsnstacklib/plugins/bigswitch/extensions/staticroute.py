# Copyright 2016 Big Switch Networks, Inc.
# All Rights Reserved
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

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception
from oslo_log import log as logging

from bsnstacklib.plugins.bigswitch.i18n import _

LOG = logging.getLogger(__name__)


# Router Rules Exceptions
class InvalidRouterRules(nexception.InvalidInput):
    message = _("Invalid format for router rules: %(rule)s, %(reason)s")


class RoutesExhausted(nexception.BadRequest):
    message = _("Unable to complete routes update for %(router_id)s. "
                "The number of routes exceeds the maximum %(quota)s.")


def convert_to_valid_routes(data):
    """
    Validates and converts router nexthop routes to the appropriate
    data structure
    Example argument = [{'destination': '0.0.0.0/0',
                         'nexthops': ['1.1.1.254']},
                        {'destination': '10.1.1.20/24',
                         'nexthops': ['1.1.1.254', '1.1.1.253']}
                       ]
    """
    V4ANY = '0.0.0.0/0'
    CIDRALL = ['any', 'external']
    if not isinstance(data, list):
        emsg = _("Invalid data format for router static routes: '%s'") % data
        LOG.debug(emsg)
        raise nexception.InvalidInput(error_message=emsg)
    _validate_uniqueroutes(data)
    routes = []
    expected_keys = ['destination', 'nexthops']
    for route in data:
        route['nexthops'] = route.get('nexthops', [])
        if not isinstance(route['nexthops'], list):
            route['nexthops'] = route['nexthops'].split('+')

        dst = (V4ANY if route['destination'] in CIDRALL
               else route['destination'])

        errors = [attr._verify_dict_keys(expected_keys, route, False),
                  attr._validate_subnet(dst),
                  _validate_nexthops(route['nexthops'])]
        errors = [m for m in errors if m]
        if errors:
            LOG.debug(errors)
            raise nexception.InvalidInput(error_message=errors)
        routes.append(route)
    return routes


def _validate_nexthops(nexthops):
    seen = []
    for ip in nexthops:
        msg = attr._validate_ip_address(ip)
        if ip in seen:
            msg = _("Duplicate nexthop in route '%s'") % ip
        seen.append(ip)
        if msg:
            return msg


def _validate_uniqueroutes(routes):
    pairs = []
    for r in routes:
        if ('destination' not in r or 'nexthops' not in r):
            continue
        pairs.append((r['destination'], r['nexthops']))

    if len(set(pairs)) != len(pairs):
        error = _("Duplicate router nexthop routes (dst,nexthops) "
                  "found '%s'") % pairs
        LOG.debug(error)
        raise nexception.InvalidInput(error_message=error)


class Staticroute(object):

    @classmethod
    def get_name(cls):
        return "Neutron Router Static Route"

    @classmethod
    def get_alias(cls):
        return "routes"

    @classmethod
    def get_description(cls):
        return "Static Route configuration for L3 router"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/routes/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2016-07-11T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'routes': {'allow_post': False, 'allow_put': True,
                   'convert_to': convert_to_valid_routes,
                   'is_visible': True,
                   'default': attr.ATTR_NOT_SPECIFIED},
    }
}
