# Copyright 2013, Big Switch Networks
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

from bsnstacklib.plugins.bigswitch.db import routerrule_db
from bsnstacklib.plugins.bigswitch.extensions import routerrule
from netaddr import IPNetwork
from neutron.common import exceptions as n_exc
from neutron.db import l3_db
from oslo_config import cfg
from oslo_log import log as logging

# number of fields in a router rule string
ROUTER_RULE_COMPONENT_COUNT = 5
LOG = logging.getLogger(__name__)
RouterRule = routerrule_db.BsnRouterRule
NextHop = routerrule_db.BsnNextHop

# Constant for now, can be exposed via properties file
MAX_PRIORITY = 3000
MIN_PRIORITY_DIFF = 10
DEFAULT_RULE_PRIORITY = -1


class IPCidr(IPNetwork):
    def __init__(self, addr, version=None):
        if addr == 'any':
            addr = '0.0.0.0/0'
        super(IPCidr, self).__init__(addr, version=version)


class RouterRule_db_mixin(l3_db.L3_NAT_db_mixin):
    """Mixin class to support route rule configuration on a router."""
    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if 'router_rules' in r:
                self._update_router_rules(context,
                                          router_db,
                                          r['router_rules'])

            updated = super(RouterRule_db_mixin, self).update_router(
                context, id, router)
            updated['router_rules'] = self._get_router_rules_by_router_id(
                context, id)

        return updated

    def create_router(self, context, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = super(RouterRule_db_mixin, self).create_router(
                context, router)
            if 'router_rules' in r:
                LOG.debug('CREATE ROUTER with router from DB %s' % router_db)
                # create default rules if needed
                all_rules = (context.session.query(RouterRule)
                             .filter_by(tenant_id=r['tenant_id'])
                             .all())
                LOG.debug('Existing rules for given tenant are %s'
                          % str(all_rules))

                existing_rule_priorities = [int(old_rule['priority'])
                                            for old_rule in all_rules]
                for rule in r['router_rules']:
                    if self._is_rule_in_set_ignore_priority(all_rules, rule):
                        pass
                    else:
                        new_prio = self._get_priority(existing_rule_priorities)
                        new_rule = RouterRule(
                            priority=new_prio,
                            tenant_id=r['tenant_id'],
                            router_id=router_db['id'],
                            destination=rule['destination'],
                            source=rule['source'],
                            action=rule['action'],
                            nexthops=[NextHop(nexthop=hop)
                                      for hop in rule['nexthops']])
                        context.session.add(new_rule)
                        existing_rule_priorities.append(new_prio)

            router_db['router_rules'] = self._get_router_rules_by_router_id(
                context, router_db['id'])
            LOG.debug('Router created as %s' % router_db)

        return router_db

    def delete_router(self, context, router_id):
        router = super(RouterRule_db_mixin, self).get_router(
            context, router_id)
        with context.session.begin(subtransactions=True):
            if 'router_rules' in router:
                LOG.debug("Deleting all rules for router_id %s" % router['id'])
                (context.session.query(RouterRule)
                 .filter_by(tenant_id=router['tenant_id'])
                 .filter_by(router_id=router['id'])
                 .delete(synchronize_session='fetch'))
                context.session.flush()
            super(RouterRule_db_mixin, self).delete_router(context, router_id)

    def apply_default_post_delete(self, context, tenant_id):
        """
        After deletion of router, check if defaults need to be applied to
        another router
        """
        with context.session.begin(subtransactions=True):
            tenant_rules = (context.session.query(RouterRule)
                            .filter_by(tenant_id=tenant_id).all())

            if not tenant_rules:
                # tenant doesn't have another router, return
                LOG.debug("Tenant doesn't have another router, return!")
                return

            # If the default rules were associated with that router, add it
            # again with the next available router
            default_rules = self._get_tenant_default_router_rules(tenant_id)
            for def_rule in default_rules:
                if self._is_rule_in_set_ignore_priority(tenant_rules,
                                                        def_rule):
                    # either all defaults are removed or none are
                    # since one rule is present, return, we're good
                    LOG.debug('Default rule %s present, returning!' % def_rule)
                    return

            # default rules not found in existing list and another router
            # exists add default rules with the next available router
            existing_router_id = tenant_rules[0]['router_id']
            existing_prio_list = [int(rule['priority'])
                                  for rule in tenant_rules]
            for def_rule in default_rules:
                new_prio = self._get_priority(existing_prio_list)
                new_rule = RouterRule(
                    priority=new_prio,
                    tenant_id=tenant_id,
                    router_id=existing_router_id,
                    destination=def_rule['destination'],
                    source=def_rule['source'],
                    action=def_rule['action'],
                    nexthops=[NextHop(nexthop=hop)
                              for hop in def_rule['nexthops']])
                context.session.add(new_rule)
                existing_prio_list.append(new_prio)

            # flush before requery
            context.session.flush()
            # return the updated router object
            router = super(RouterRule_db_mixin, self).get_router(
                context, existing_router_id)
            router['router_rules'] = self._get_router_rules_by_router_id(
                context, id)
            LOG.debug('Returning router obj after applying default rules %s'
                      % router)
            return router

    def _get_priority(self, existing_rule_priorities):
        new_prio = MAX_PRIORITY
        while new_prio in existing_rule_priorities:
            new_prio = new_prio - 1
        if new_prio < 1:
            raise("All router rule priorities are exhausted!")
        return new_prio

    def _update_router_rules(self, context, router, rules):
        """
        Update router rules at the tenant level. Since at the backend, BCF
        maintains a single logical router, all routers under the tenant map to
        a single router on the backend.
        Hence, we apply policies accordingly.
        """
        if len(rules) > cfg.CONF.ROUTER.max_router_rules:
            raise routerrule.RulesExhausted(
                router_id=router['id'],
                quota=cfg.CONF.ROUTER.max_router_rules)

        LOG.debug('Update router ::: %s', router)
        LOG.debug('Filtering by tenantID %s routerID %s'
                  % (router['tenant_id'], router['id']))
        old_rules = (context.session.query(RouterRule)
                     .filter_by(tenant_id=router['tenant_id'])
                     .filter_by(router_id=router['id']).all())
        old_rules_list = self._make_router_rule_list(old_rules)
        LOG.debug('Existing router rules::: %s', old_rules_list)

        overlapping_rules, deleted_rules, added_rules = \
            self._get_rule_diff(old_rules_list, rules)

        LOG.debug('Updated_rules %s \n Deleted_rules %s \n Added_rules %s \n'
                  % (overlapping_rules, deleted_rules, added_rules))

        for rule in overlapping_rules:
            for old_rule in old_rules:
                if int(rule['priority']) != old_rule.priority:
                    continue
                if self._is_rule_equal(old_rule, rule):
                    continue
                old_rule.update(rule)

        for rule in deleted_rules:
            (context.session.query(RouterRule)
             .filter_by(tenant_id=router['tenant_id'])
             .filter_by(priority=rule['priority'])
             .delete())

        for rule in added_rules:
            new_rule = RouterRule(
                priority=rule['priority'],
                tenant_id=router['tenant_id'],
                router_id=router['id'],
                destination=rule['destination'],
                source=rule['source'],
                action=rule['action'],
                nexthops=[NextHop(nexthop=hop)
                          for hop in rule['nexthops']])
            context.session.add(new_rule)

        context.session.flush()

    def _is_rule_equal(self, old_rule, rule, ignore_priority=False):
        """
        Compare the necessary fields of two given rules for equality
        """
        if ignore_priority:
            if (rule['source'] == old_rule['source']
                and rule['destination'] == old_rule['destination']
                and rule['action'] == old_rule['action']):
                return True
        else:
            if (rule['source'] == old_rule['source']
                and rule['destination'] == old_rule['destination']
                and rule['action'] == old_rule['action']
                and rule['priority'] == old_rule['priority']):
                return True
        return False

    def _is_rule_in_set_ignore_priority(self, rule_list, rule):
        """Check if the given rule is present in the rule_list. Ignores the
        priority of the rule

        :param rule_list: list of existing rules in dictionary format
        :param rule: new rule to be added
        :return boolean:
        """
        for old_rule in rule_list:
            if self._is_rule_equal(old_rule, rule, True):
                return True
        return False

    def _is_rule_in_set(self, rule, rule_list):
        """Check if the given rule is present in the rule_list

        :param rule_list: list of existing rules in dictionary format
        :param rule: new rule to be added
        :return boolean:
        """
        for old_rule in rule_list:
            if self._is_rule_equal(old_rule, rule):
                return True
        return False

    def _get_rule_diff(self, old_ruleset, new_ruleset):
        """
        Given two sets of rules, find overlapping, added and removed rules.
        """
        existing_priorities = [int(rule['priority']) for rule in old_ruleset]

        overlapping_rules = [rule for rule in new_ruleset
                         if int(rule['priority']) in existing_priorities]
        overlapping_priorities = [int(rule['priority'])
                                  for rule in overlapping_rules]

        added_rules = [rule for rule in new_ruleset
                       if (not self._is_rule_in_set(rule, old_ruleset)
                           and int(rule['priority'])
                           not in overlapping_priorities)]

        deleted_rules = [rule for rule in old_ruleset
                         if not self._is_rule_in_set(rule, new_ruleset) and
                         int(rule['priority']) not in overlapping_priorities]

        return overlapping_rules, deleted_rules, added_rules

    def _get_tenant_default_router_rules(self, tenant):
        rules = cfg.CONF.ROUTER.tenant_default_router_rule
        default_set = []
        tenant_set = []
        for rule in rules:
            items = rule.split(':')
            # put an empty string on the end if nexthops wasn't specified
            if len(items) < ROUTER_RULE_COMPONENT_COUNT:
                items.append('')
            try:
                (tenant_id, source, destination, action, nexthops) = items
            except ValueError:
                continue
            parsed_rule = {'priority': -1,
                           'source': source,
                           'destination': destination,
                           'action': action,
                           'nexthops': [hop for hop in nexthops.split(',')
                                        if hop]}
            if tenant_id == '*':
                default_set.append(parsed_rule)
            if tenant_id == tenant:
                tenant_set.append(parsed_rule)
        return tenant_set if tenant_set else default_set

    def _make_router_rule_list(self, router_rules):
        ruleslist = []
        for rule in router_rules:
            hops = [hop['nexthop'] for hop in rule['nexthops']]
            ruleslist.append({'id': rule['id'],
                              'priority': rule['priority'],
                              'destination': rule['destination'],
                              'source': rule['source'],
                              'action': rule['action'],
                              'nexthops': hops})
        return ruleslist

    def _get_router_rules_by_router_id(self, context, id):
        query = context.session.query(RouterRule)
        router_rules = query.filter_by(router_id=id).all()
        return self._make_router_rule_list(router_rules)

    def _get_tenant_id_for_create(self, context, resource):
        if context.is_admin and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context.tenant_id):
            reason = _('Cannot create resource for another tenant')
            raise n_exc.AdminRequired(reason=reason)
        else:
            tenant_id = context.tenant_id
        return tenant_id

    def get_router(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            router = super(RouterRule_db_mixin, self).get_router(
                context, id, fields)
            router['router_rules'] = self._get_router_rules_by_router_id(
                context, id)
            return router

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with context.session.begin(subtransactions=True):
            routers = super(RouterRule_db_mixin, self).get_routers(
                context, filters, fields, sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse)
            for router in routers:
                router['router_rules'] = self._get_router_rules_by_router_id(
                    context, router['id'])
            return routers

    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            routers = super(RouterRule_db_mixin,
                            self).get_sync_data(context, router_ids,
                                                active=active)
            for router in routers:
                router['router_rules'] = self._get_router_rules_by_router_id(
                    context, router['id'])
        return routers
