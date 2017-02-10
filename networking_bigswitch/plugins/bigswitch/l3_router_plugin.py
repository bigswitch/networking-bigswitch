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
#

"""
Neutron L3 REST Proxy Plugin for Big Switch and Floodlight Controllers.

This plugin handles the L3 router calls for Big Switch Floodlight deployments.
It is intended to be used in conjunction with the Big Switch ML2 driver or the
Big Switch core plugin.
"""
from oslo_log import helpers as log_helper
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.api import extensions as neutron_extensions
from neutron.common import exceptions
from neutron.db import l3_db
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants

from networking_bigswitch.plugins.bigswitch import extensions
from networking_bigswitch.plugins.bigswitch.i18n import _
from networking_bigswitch.plugins.bigswitch.i18n import _LE
from networking_bigswitch.plugins.bigswitch import plugin as cplugin
from networking_bigswitch.plugins.bigswitch import routerrule_db
from networking_bigswitch.plugins.bigswitch import servermanager

LOG = logging.getLogger(__name__)
put_context_in_serverpool = cplugin.put_context_in_serverpool
BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH = ("BCF does "
    "not have floatingip capability, should not "
    "deploy BSN l3 router plugin")


class L3RestProxy(cplugin.NeutronRestProxyV2Base,
                  routerrule_db.RouterRule_db_mixin):

    supported_extension_aliases = ["router", "router_rules"]
    # This is a flag to tell that L3 plugin is BSN.
    bsn = True

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        return _("L3 Router Service Plugin for Big Switch fabric")

    def __init__(self):
        # Include the Big Switch Extensions path in the api_extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        super(L3RestProxy, self).__init__()
        self.servers = servermanager.ServerPool.get_instance()

    @put_context_in_serverpool
    @log_helper.log_method_call
    def create_router(self, context, router):
        self._warn_on_state_status(router['router'])

        tenant_id = self._get_tenant_id_for_create(context, router["router"])

        # set default router rules
        rules = self._get_tenant_default_router_rule(tenant_id)
        router['router']['router_rules'] = [rules]

        with context.session.begin(subtransactions=True):
            # create router in DB
            new_router = super(L3RestProxy, self).create_router(context,
                                                                router)
            mapped_router = self._map_tenant_name(new_router)
            mapped_router = self._map_state_and_status(mapped_router)
            # populate external tenant_id if it is absent for external network,
            # This is a new work flow in kilo that user can specify external
            # network when creating a router
            if (mapped_router and mapped_router.get('external_gateway_info')):
                ext_gw_info = mapped_router.get('external_gateway_info')
                ext_net_id = ext_gw_info.get('network_id')
                ext_tenant_id = ext_gw_info.get("tenant_id")
                if ext_net_id and (not ext_tenant_id):
                    ext_net = self.get_network(context, ext_net_id)
                    if ext_net:
                        mapped_router['external_gateway_info']['tenant_id'] = (
                            ext_net.get('tenant_id'))
            # pop router_tenant_rules from upstream object
            if 'router_tenant_rules' in new_router:
                del new_router['router_tenant_rules']

            self.servers.rest_create_router(tenant_id, mapped_router)

            # return created router
            return new_router

    @put_context_in_serverpool
    @log_helper.log_method_call
    def update_router(self, context, router_id, router):
        self._warn_on_state_status(router['router'])

        orig_router = super(L3RestProxy, self).get_router(context, router_id)
        tenant_id = orig_router["tenant_id"]
        with context.session.begin(subtransactions=True):
            new_router = super(L3RestProxy,
                               self).update_router(context, router_id, router)
            router = self._update_ext_gateway_info(context, new_router)
            # pop router_tenant_rules from upstream object
            if 'router_tenant_rules' in new_router:
                del new_router['router_tenant_rules']
            # update router on network controller
            self.servers.rest_update_router(tenant_id, router, router_id)

            # return updated router
            return new_router

    @put_context_in_serverpool
    @log_helper.log_method_call
    def delete_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            orig_router = self._get_router(context, router_id)
            tenant_id = orig_router["tenant_id"]

            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_owner = l3_db.DEVICE_OWNER_ROUTER_INTF
            device_filter = {'device_id': [router_id],
                             'device_owner': [device_owner]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)
            super(L3RestProxy, self).delete_router(context, router_id)

            # added check to update router policy for another router for
            # default routes
            updated_router = (super(L3RestProxy, self)
                              .update_policies_post_delete(context, tenant_id))

            # delete from network controller
            self.servers.rest_delete_router(tenant_id, router_id)
            if updated_router:
                # update BCF after removing the router first
                LOG.debug('Default policies now part of router: %s'
                          % updated_router)
                router = self._update_ext_gateway_info(context, updated_router)
                self.servers.rest_update_router(tenant_id, router,
                                                router['id'])

    @put_context_in_serverpool
    @log_helper.log_method_call
    def add_router_interface(self, context, router_id, interface_info):
        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        with context.session.begin(subtransactions=True):
            # create interface in DB
            new_intf_info = super(L3RestProxy,
                                  self).add_router_interface(context,
                                                             router_id,
                                                             interface_info)
            port = self._get_port(context, new_intf_info['port_id'])
            subnet_id = new_intf_info['subnet_id']
            # we will use the port's subnet id as interface's id
            intf_details = self._get_router_intf_details(context,
                                                         subnet_id)

            # get gateway_ip from port instead of gateway_ip
            if port.get("fixed_ips"):
                intf_details['ip_address'] = port["fixed_ips"][0]['ip_address']

            # create interface on the network controller
            self.servers.rest_add_router_interface(tenant_id, router_id,
                                                   intf_details)
        manager.NeutronManager.get_plugin().update_port(
            context, port['id'], {'port': {'status': 'ACTIVE'}})
        return new_intf_info

    @put_context_in_serverpool
    @log_helper.log_method_call
    def remove_router_interface(self, context, router_id, interface_info):
        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # we will first get the interface identifier before deleting in the DB
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port = self._get_port(context, interface_info['port_id'])
            interface_id = port['fixed_ips'][0]['subnet_id']
        elif 'subnet_id' in interface_info:
            subnet = self._get_subnet(context, interface_info['subnet_id'])
            interface_id = subnet['id']
        else:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)

        with context.session.begin(subtransactions=True):
            # remove router in DB
            del_ret = super(L3RestProxy,
                            self).remove_router_interface(context,
                                                          router_id,
                                                          interface_info)

            # create router on the network controller
            self.servers.rest_remove_router_interface(tenant_id, router_id,
                                                      interface_id)
            return del_ret

    # add floating_port_id into the dict for later port mac lookup
    def _make_floatingip_dict(self, floatingip, fields=None,
                              process_extensions=True):
        res = super(L3RestProxy, self)._make_floatingip_dict(
            floatingip, fields=fields,
            process_extensions=process_extensions)
        res['floating_port_id'] = floatingip['floating_port_id']
        return self._fields(res, fields)

    @put_context_in_serverpool
    @log_helper.log_method_call
    def create_floatingip(self, context, floatingip):
        with context.session.begin(subtransactions=True):
            # create floatingip in DB
            new_fl_ip = super(L3RestProxy,
                              self).create_floatingip(context, floatingip)

            # create floatingip on the network controller
            try:
                if 'floatingip' in self.servers.get_capabilities():
                    self.servers.rest_create_floatingip(
                        new_fl_ip['tenant_id'], new_fl_ip)
                else:
                    LOG.error(BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH)
                    self._send_floatingip_update(context)
            except servermanager.RemoteRestError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        _LE("NeutronRestProxyV2: Unable to create remote "
                            "floating IP: %s"), e)
            # return created floating IP
            return new_fl_ip

    @put_context_in_serverpool
    @log_helper.log_method_call
    def update_floatingip(self, context, id, floatingip):
        with context.session.begin(subtransactions=True):
            # update floatingip in DB
            new_fl_ip = super(L3RestProxy,
                              self).update_floatingip(context, id, floatingip)
            # add mac address for the port
            if new_fl_ip.get('floating_port_id'):
                fport = self.get_port(context.elevated(),
                                      new_fl_ip['floating_port_id'])
                new_fl_ip['floating_mac_address'] = fport.get('mac_address')

            # update network on network controller
            if 'floatingip' in self.servers.get_capabilities():
                self.servers.rest_update_floatingip(new_fl_ip['tenant_id'],
                                                    new_fl_ip, id)
            else:
                LOG.error(BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH)
                self._send_floatingip_update(context)
            return new_fl_ip

    @put_context_in_serverpool
    @log_helper.log_method_call
    def delete_floatingip(self, context, id):
        with context.session.begin(subtransactions=True):
            # delete floating IP in DB
            old_fip = super(L3RestProxy, self).get_floatingip(context, id)
            super(L3RestProxy, self).delete_floatingip(context, id)

            # update network on network controller
            if 'floatingip' in self.servers.get_capabilities():
                self.servers.rest_delete_floatingip(old_fip['tenant_id'], id)
            else:
                LOG.error(BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH)
                self._send_floatingip_update(context)

    @put_context_in_serverpool
    @log_helper.log_method_call
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        router_ids = super(L3RestProxy, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)
        self._send_floatingip_update(context)
        return router_ids

    # overriding method from l3_db as original method calls
    # self.delete_floatingip() which in turn calls self.delete_port() which
    # is locked with 'bsn-port-barrier'
    @put_context_in_serverpool
    def delete_disassociated_floatingips(self, context, network_id):
        query = self._model_query(context, l3_db.FloatingIP)
        query = query.filter_by(floating_network_id=network_id,
                                fixed_port_id=None,
                                router_id=None)
        for fip in query:
            context.session.delete(fip)
            self._delete_port(context.elevated(), fip['floating_port_id'])

    def _update_ext_gateway_info(self, context, updated_router):
        if updated_router.get(l3.EXTERNAL_GW_INFO):
            ext_net_id = updated_router[l3.EXTERNAL_GW_INFO].get('network_id')
            ext_net = self.get_network(context, ext_net_id)
            ext_tenant_id = ext_net.get('tenant_id')
            if ext_tenant_id:
                updated_router[l3.EXTERNAL_GW_INFO]['tenant_id'] = (
                    ext_tenant_id)
        router = self._map_tenant_name(updated_router)
        router = self._map_state_and_status(router)
        # look up the network on this side to save an expensive query on
        # the backend controller.
        if router and router.get('external_gateway_info'):
            router['external_gateway_info']['network'] = self.get_network(
                context.elevated(),
                router['external_gateway_info']['network_id'])
        return router

    def _send_floatingip_update(self, context):
        try:
            ext_net_id = self.get_external_network_id(context)
            if ext_net_id:
                # Use the elevated state of the context for the ext_net query
                admin_context = context.elevated()
                ext_net = super(L3RestProxy,
                                self).get_network(admin_context, ext_net_id)
                # update external network on network controller
                self._send_update_network(ext_net, admin_context)
        except exceptions.TooManyExternalNetworks:
            # get_external_network can raise errors when multiple external
            # networks are detected, which isn't supported by the Plugin
            LOG.error(_LE("NeutronRestProxyV2: too many external networks"))
