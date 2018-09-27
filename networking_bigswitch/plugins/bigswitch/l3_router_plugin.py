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
import copy

from oslo_log import helpers as log_helper
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.api import extensions as neutron_extensions
from neutron.db import api as db
from neutron.db import dns_db
from neutron.db import l3_db


from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from networking_bigswitch.plugins.bigswitch.db import tenant_policy_db
from networking_bigswitch.plugins.bigswitch import extensions
from networking_bigswitch.plugins.bigswitch.i18n import _
from networking_bigswitch.plugins.bigswitch.i18n import _LE
from networking_bigswitch.plugins.bigswitch import plugin as cplugin
from networking_bigswitch.plugins.bigswitch import servermanager
from networking_bigswitch.plugins.bigswitch.utils import Util

LOG = logging.getLogger(__name__)
add_debug_log = cplugin.add_debug_log
BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH = (
    "BCF does not have floatingip capability, should not "
    "deploy BSN l3 router plugin")
BSN_TRANSACTION_ID = 'bsn_transaction_id'


class TransactionCache(object):
    """Cache to store the object ID generated during create operations.

    This cache only temporarily stores the ID assigned to a new object during
    create operation.
    If the operation fails, the cache is used to retrieve the ID assigned to
    the object to delete it from the BCF controller.

    Cache is a dict storing the transaction to object ID mapping:
    {
        'transaction_1': 'object_id_1',
        'transaction_2': 'object_id_2',
        ..
        'transaction_n': 'object_id_n'
    }
    """
    def __init__(self):
        self.cache = {}

    def add_transaction(self, transaction_id, obj_id):
        """Adds txn_id > obj_id mapping to the cache

        :param transaction_id: unique bsn_transaction_id generated
        :param obj_id: ID assigned to the object during DB create
        :return: None
        """
        LOG.debug('Adding mapping to transaction cache for transaction_id '
                  '%(txn_id)s to object_id %(obj_id)s.',
                  {'txn_id': transaction_id, 'obj_id': obj_id})
        self.cache[transaction_id] = obj_id

    def remove_transaction(self, transaction_id):
        """Removes the transaction_id from cache

        :param transaction_id: unique bsn_transaction_id for the current
                               operation
        :return: obj_id assigned previously or None
        """
        if transaction_id not in self.cache:
            LOG.debug('Transaction ID %(txn_id)s not found in cache. Maybe an '
                      'exception caused pre-emptive removal.',
                      {'txn_id': transaction_id})
            return None
        obj_id = self.cache.pop(transaction_id)
        LOG.debug('Removing mapping from transaction_cache for transaction_id '
                  '%(txn_id)s to object_id %(obj_id)s.',
                  {'obj_id': obj_id, 'txn_id': transaction_id})
        return obj_id


class L3RestProxy(cplugin.NeutronRestProxyV2Base,
                  l3_db.L3_NAT_db_mixin,
                  dns_db.DNSDbMixin,
                  tenant_policy_db.TenantPolicyDbMixin):

    supported_extension_aliases = ["router"]
    # This is a flag to tell that L3 plugin is BSN.
    bsn = True

    @staticmethod
    def get_plugin_type():
        return plugin_constants.L3

    @staticmethod
    def get_plugin_description():
        return _("L3 Router Service Plugin for Big Switch fabric")

    def __init__(self):
        # Include the Big Switch Extensions path in the api_extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        super(L3RestProxy, self).__init__()
        self.servers = servermanager.ServerPool.get_instance()
        self.subscribe_l3_callbacks()
        # upstream stores ID of the object being created as part of the
        # safe_creation method
        # we don't have access to that local variable. hence we need to stash
        # it when it comes as part of before_create_callback
        # TransactionCache is a dict with the following mapping:
        # {'bsn_transaction_id': 'object_id'}
        self.txn_cache = TransactionCache()

    def subscribe_l3_callbacks(self):
        registry.subscribe(self.router_before_create_callback,
                           resources.ROUTER, events.BEFORE_CREATE)
        registry.subscribe(self.router_after_create_callback, resources.ROUTER,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_precommit_delete_callback,
                           resources.ROUTER, events.PRECOMMIT_DELETE)
        registry.subscribe(self.router_after_delete_callback, resources.ROUTER,
                           events.AFTER_DELETE)
        registry.subscribe(self.router_interface_before_create_callback,
                           resources.ROUTER_INTERFACE, events.BEFORE_CREATE)
        registry.subscribe(self.router_interface_after_create_callback,
                           resources.ROUTER_INTERFACE, events.AFTER_CREATE)

    @log_helper.log_method_call
    def router_before_create_callback(self, resource, event, trigger,
                                      **kwargs):
        """Try to create router on BCF

        If failed, rollback the DB operation.
        :return:
        """
        context = kwargs.get('context')
        router = kwargs.get('router')
        self.txn_cache.add_transaction(router[BSN_TRANSACTION_ID],
                                       router['id'])
        with db.context_manager.reader.using(context):
            mapped_router = self._map_display_name_or_tenant(router)
            mapped_router = self._map_state_and_status(mapped_router)

            # Does not handle external gateway and some other information
            self.servers.rest_create_router(mapped_router['tenant_id'],
                                            mapped_router)

    @log_helper.log_method_call
    def router_after_create_callback(self, resource, event, trigger, **kwargs):
        """Update external gateway and create tenant policies

        :param resource:
        :param event:
        :param trigger:
        :param kwargs:
        :return:
        """
        context = kwargs.get('context')
        router = kwargs.get('router')
        tenant_id = router['tenant_id']
        # set default router policies
        default_policy_dict = self._get_tenant_default_router_policy(tenant_id)

        with db.context_manager.writer.using(context):
            mapped_router = self._map_display_name_or_tenant(router)
            mapped_router = self._map_state_and_status(mapped_router)
            # populate external tenant_id if it is absent for external network,
            # This is a new work flow in kilo that user can specify external
            # network when creating a router
            if mapped_router and mapped_router.get('external_gateway_info'):
                ext_gw_info = mapped_router.get('external_gateway_info')
                ext_net_id = ext_gw_info.get('network_id')
                ext_tenant_id = ext_gw_info.get("tenant_id")
                if ext_net_id and (not ext_tenant_id):
                    ext_net = self.get_network(context, ext_net_id)
                    if ext_net:
                        mapped_router['external_gateway_info']['tenant_id'] = (
                            ext_net.get('tenant_id'))
            # update router that was created in before_create callback
            self.servers.rest_update_router(
                mapped_router['tenant_id'], mapped_router, mapped_router['id'])

            # post router creation, create default policy if missing
            tenantpolicy_dict = super(L3RestProxy, self).create_default_policy(
                context, tenant_id, default_policy_dict)
            if tenantpolicy_dict:
                self.servers.rest_create_tenantpolicy(
                    tenantpolicy_dict['tenant_id'], tenantpolicy_dict)

    @add_debug_log
    @log_helper.log_method_call
    def create_router(self, context, router):
        self._warn_on_state_status(router['router'])
        # this also validates if the current tenant can create this router
        tenant_id = Util.get_tenant_id_for_create(context, router['router'])
        # cache the transaction_id
        bsn_transaction_id = uuidutils.generate_uuid()
        # add this unique identifier to the router object upstream, so that it
        # reaches the pre-commit callback
        router['router'][BSN_TRANSACTION_ID] = bsn_transaction_id
        try:
            new_router = super(L3RestProxy, self).create_router(context,
                                                                router)
            return new_router
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    router_id = self.txn_cache.remove_transaction(
                        bsn_transaction_id)
                    self.servers.rest_delete_router(tenant_id, router_id)
                except Exception as e:
                    LOG.error(_LE("Cannot clean up the router object created "
                                  "on BCF. Exception: %(exc)s"), {'exc': e})
        finally:
            self.txn_cache.remove_transaction(bsn_transaction_id)

    @add_debug_log
    @log_helper.log_method_call
    def update_router(self, context, router_id, router):
        self._warn_on_state_status(router['router'])

        orig_router = super(L3RestProxy, self).get_router(context, router_id)
        tenant_id = orig_router["tenant_id"]
        with db.context_manager.writer.using(context):
            setattr(context, 'GUARD_TRANSACTION', False)
            new_router = super(L3RestProxy,
                               self).update_router(context, router_id, router)
            router = self._update_ext_gateway_info(context, new_router)

            # update router on network controller
            self.servers.rest_update_router(tenant_id, router, router_id)

            # return updated router
            return new_router

    @log_helper.log_method_call
    def router_precommit_delete_callback(self, resource, event, trigger,
                                         **kwargs):
        router = kwargs.get('router_db')
        router_id = kwargs.get('router_id')

        # delete from network controller
        self.servers.rest_delete_router(router['tenant_id'], router_id)

    @log_helper.log_method_call
    def router_after_delete_callback(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context')
        orig_router = kwargs.get('original')
        tenant_id = orig_router['tenant_id']

        # remove tenant policies if this was the last router under tenant
        with db.context_manager.writer.using(context):
            upstream_routers = super(L3RestProxy, self).get_routers(
                context, filters={"tenant_id": [tenant_id]})

            LOG.debug('upstream_routers are: %s', upstream_routers)
            if not upstream_routers:
                # there aren't any routers under tenant. remove all policies
                super(L3RestProxy, self).remove_default_policy(context,
                                                               tenant_id)

    @add_debug_log
    @log_helper.log_method_call
    def delete_router(self, context, router_id):
        with db.context_manager.reader.using(context):
            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise exceptions.l3.RouterInUse(router_id=router_id)

            device_owner = lib_constants.DEVICE_OWNER_ROUTER_INTF
            device_filter = {'device_id': [router_id],
                             'device_owner': [device_owner]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise exceptions.l3.RouterInUse(router_id=router_id)

        super(L3RestProxy, self).delete_router(context, router_id)

    @log_helper.log_method_call
    def router_interface_before_create_callback(self, resource, event, trigger,
                                                **kwargs):
        context = kwargs.get('context')
        router = kwargs.get('router_db')
        port = kwargs.get('port')
        interface_info = kwargs.get('interface_info')
        router_id = kwargs.get('router_id')

        if 'port_id' in interface_info:
            subnet_id = port['fixed_ips'][0]['subnet_id']
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
        else:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)

        # bookmark for delete in case of transaction rollback
        self.txn_cache.add_transaction(interface_info[BSN_TRANSACTION_ID],
                                       subnet_id)
        with db.context_manager.reader.using(context):
            # we will use the port's subnet id as interface's id
            intf_details = self._get_router_intf_details(context, port,
                                                         subnet_id)

            # create interface on the network controller
            self.servers.rest_add_router_interface(
                router['tenant_id'], router_id, intf_details)

    @log_helper.log_method_call
    def router_interface_after_create_callback(self, resource, event, trigger,
                                               **kwargs):
        context = kwargs.get('context')
        port = kwargs.get('port')

        directory.get_plugin().update_port(context, port['id'],
                                           {'port': {'status': 'ACTIVE'}})

    @add_debug_log
    @log_helper.log_method_call
    def add_router_interface(self, context, router_id, interface_info):
        bsn_transaction_id = uuidutils.generate_uuid()
        interface_info[BSN_TRANSACTION_ID] = bsn_transaction_id
        try:
            new_intf_info = super(L3RestProxy, self).add_router_interface(
                context, router_id, interface_info)
            return new_intf_info
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    router = self._get_router(context, router_id)
                    tenant_id = router['tenant_id']
                    interface_id = self.txn_cache.remove_transaction(
                        bsn_transaction_id)
                    # we use port's subnet_id as interface's id
                    self.servers.rest_remove_router_interface(
                        tenant_id, router_id, interface_id)
                except Exception as e:
                    LOG.error(_LE("Cannot clean up router interface created "
                                  "on BCF. Exception: %(exc)s"), {'exc': e})
        finally:
            self.txn_cache.remove_transaction(bsn_transaction_id)

    @add_debug_log
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

        with db.context_manager.writer.using(context):
            # remove router in DB
            # TODO(wolverineav): hack until fixed at right place
            setattr(context, 'GUARD_TRANSACTION', False)
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

    @add_debug_log
    @log_helper.log_method_call
    def create_floatingip(self, context, floatingip):
        with db.context_manager.writer.using(context):
            # create floatingip in DB
            # TODO(wolverineav): hack until fixed at right place
            setattr(context, 'GUARD_TRANSACTION', False)
            new_fl_ip = super(L3RestProxy,
                              self).create_floatingip(context, floatingip)

            # create floatingip on the network controller
            try:
                if 'floatingip' in self.servers.get_capabilities():
                    backend_fip = copy.deepcopy(new_fl_ip)
                    fport = self.get_port(context.elevated(),
                                          backend_fip['floating_port_id'])
                    backend_fip['floating_mac_address']\
                        = fport.get('mac_address')
                    self.servers.rest_create_floatingip(
                        backend_fip['tenant_id'], backend_fip)
                else:
                    LOG.error(BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH)
                    self._send_floatingip_update(context)
            except servermanager.RemoteRestError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error("NeutronRestProxyV2: Unable to create remote "
                              "floating IP: %s", e)
            # return created floating IP
            return new_fl_ip

    @add_debug_log
    @log_helper.log_method_call
    def update_floatingip(self, context, id, floatingip):
        with db.context_manager.writer.using(context):
            # update floatingip in DB
            # TODO(wolverineav): hack until fixed at right place
            setattr(context, 'GUARD_TRANSACTION', False)
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

    @add_debug_log
    @log_helper.log_method_call
    def delete_floatingip(self, context, id):
        with db.context_manager.writer.using(context):
            # delete floating IP in DB
            # TODO(wolverineav): hack until fixed at right place
            setattr(context, 'GUARD_TRANSACTION', False)
            old_fip = super(L3RestProxy, self).get_floatingip(context, id)
            super(L3RestProxy, self).delete_floatingip(context, id)

            # update network on network controller
            if 'floatingip' in self.servers.get_capabilities():
                self.servers.rest_delete_floatingip(old_fip['tenant_id'], id)
            else:
                LOG.error(BCF_CAPABILITY_L3_PLUGIN_MISS_MATCH)
                self._send_floatingip_update(context)

    @add_debug_log
    @log_helper.log_method_call
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        router_ids = super(L3RestProxy, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)
        self._send_floatingip_update(context)
        return router_ids

    def _update_ext_gateway_info(self, context, updated_router):
        if updated_router.get(l3_apidef.EXTERNAL_GW_INFO):
            ext_net_id = (updated_router[l3_apidef.EXTERNAL_GW_INFO]
                          .get('network_id'))
            ext_net = self.get_network(context, ext_net_id)
            ext_tenant_id = ext_net.get('tenant_id')
            if ext_tenant_id:
                updated_router[l3_apidef.EXTERNAL_GW_INFO]['tenant_id'] = (
                    ext_tenant_id)
        router = self._map_display_name_or_tenant(updated_router)
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
            pass
