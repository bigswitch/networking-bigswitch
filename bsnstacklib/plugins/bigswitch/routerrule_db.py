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
from bsnstacklib.plugins.bigswitch.i18n import _
import itertools
from netaddr import IPNetwork
from neutron.db import l3_db
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from sets import Set

# number of fields in a router rule string
ROUTER_RULE_COMPONENT_COUNT = 5
LOG = logging.getLogger(__name__)
RouterRule = routerrule_db.BsnRouterRule
NextHop = routerrule_db.BsnNextHop

# Constant for now, can be exposed via properties file
MAX_PRIORITY = 3000
MIN_PRIORITY_DIFF = 10


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
                self._update_router_rules(context,
                                          router_db,
                                          r['router_rules'])
            else:
                LOG.debug('No rules in router')
            router_db['router_rules'] = self._get_router_rules_by_router_id(
                context, router_db['id'])

        return router_db

    def _is_rule_in_list(self, rule_list, rule):
        """Check if the given rule is present in the rule_list

        :param rule_list: list of existing rules in dictionary format
        :param rule: new rule to be added
        :return boolean:
        """
        for old_rule in rule_list:
            if (rule['source'] == old_rule['source']
                and rule['destination'] == old_rule['destination']
                and rule['action'] == old_rule['action']
                and rule['priority'] == old_rule['priority']):
                return True
        return False

    def _get_rule_diff(self, old_rules, new_rules):
        """Given the set of old rules and new rules, get the diff rule.

        :param old_rules: list of old rule objects - dictionary
        :param new_rules: list of new rule objects - dictionary
        :return list of rule_dict: the rules present in new_rules but not in
        old_rules.
        """
        diff_list = filter(lambda x: not self._is_rule_in_list(old_rules, x),
                           new_rules)
        return diff_list

    def _get_same_action_rules(self, rules, action):
        """Given a list of rules, check and return for all rules with the same
        action.

        :param rules: list of rules
        :param action: action of type permit or deny
        :return list: of rules with same action
        """
        existing_rules = filter(lambda x: x.action == action, rules)
        return existing_rules

    def _rule_a_obstructs_rule_b(self, rule_a, rule_b):
        """Checks whether rule_a overlaps with rule_b in any way. It doesn't
        have to be a superset, just an intersection is enough.
        If nexthops don't match, that is considered as an overlap.
        """
        if ((IPCidr(rule_a.source) in IPCidr(rule_b.source)
             or IPCidr(rule_b.source) in IPCidr(rule_a.source))
            and (IPCidr(rule_a.destination) in IPCidr(rule_b.destination)
                 or IPCidr(rule_b.destination) in IPCidr(rule_a.destination))):

            if rule_a.action != rule_b.action:
                return True
            elif (rule_a.action == rule_b.action == 'permit'
                  and Set(rule_a.nexthops) != Set(rule_b.nexthops)):
                return True
            elif rule_a.action == rule_b.action == 'deny':
                return False
        return False

    def _rule_a_superset_rule_b(self, rule_a, rule_b):
        """Check if rule_a covers the source and destination of rule_b.

        :param rule_a: supposed superset rule
        :param rule_b: rule to be checked for
        :return boolean: True if rule_a is superset of rule_b. False otherwise.
        """
        # for both permit rules, first check nexthops match
        if rule_a.action == rule_b.action == 'permit':
            if (Set(nexthop.nexthop for nexthop in rule_a.nexthops) !=
                    Set(nexthop.nexthop for nexthop in rule_b.nexthops)):
                return False

        if (IPCidr(rule_b.source) in IPCidr(rule_a.source)
            and IPCidr(rule_b.destination) in IPCidr(rule_a.destination)):
            return True
        return False

    def _cleanup_priority_get_min(self, context, rules):
        """Starts priority reassignment from MAX_PRIORITY and gets the new
        min_priority

        :param context: used to delete rules from the current session
        :param rules: set of rules to be reassigned the priorities
        :return min_priority: the new minimum valid priority
        """
        min_priority = MAX_PRIORITY
        sorted_rules = sorted(rules, key=lambda k: k.priority,
                              reverse=True)
        for rule in sorted_rules:
            rule.update({'priority': min_priority})
            min_priority = min_priority - MIN_PRIORITY_DIFF
            if min_priority <= 0:
                raise Exception("All router rule priorities are exhausted")
        return min_priority

    def _min_priority(self, rules):
        """Get the minimum available priority. The difference between existing
        minimum and current priority is MIN_PRIORITY_DIFF. If existing minimum
        is <= MIN_PRIORITY_DIFF, returns False in the tuple.

        :param rules: list of existing rules with priorities
        :return tuple(boolean, min_priority):
        boolean compaction required, min_priority
        """
        min_priority = MAX_PRIORITY

        sorted_rules = sorted(rules, key=lambda k: k.priority)
        for rule in sorted_rules:
            if rule.priority <= MIN_PRIORITY_DIFF:
                return True, -1
            else:
                min_priority = rule.priority - MIN_PRIORITY_DIFF
                return False, min_priority

        return False, min_priority

    def _opposite_rule_exists(self, context, old_rules, new_rule):
        """Check if rule exists with opposite action and exact same source
        and destination
        """
        sorted_rules = sorted(old_rules, key=lambda k: k.priority,
                              reverse=True)
        opposite_action = 'permit' if new_rule.action == 'deny' else 'deny'
        for old_rule in sorted_rules:
            if (old_rule.priority >= new_rule.priority
                and old_rule.source == new_rule.source
                and old_rule.destination == new_rule.destination
                and old_rule.action == opposite_action):

                return True, old_rule

        return False, None

    def _identical_rule_exists(self, context, old_rules, new_rule):
        """Check if rule exists with same action and exact same source
        and destination
        """
        sorted_rules = sorted(old_rules, key=lambda k: k.priority,
                              reverse=True)
        for old_rule in sorted_rules:
            if (old_rule.priority >= new_rule.priority
                and old_rule.source == new_rule.source
                and old_rule.destination == new_rule.destination
                and old_rule.action == new_rule.action):

                return True, old_rule

        return False, None

    def _filter_opposite_rules(self, new_rule, rules):
        """Get list of rules with opposite action and higher priority i.e.
        lower priority number
        """
        filter_action = 'permit' if new_rule.action == 'deny' else 'deny'
        filtered_rules = []
        for rule in rules:
            if (rule.action == filter_action
                and rule.priority <= new_rule.priority):
                filtered_rules.append(rule)
        return filtered_rules

    def _remove_redundant_rules(self, context, router_id):
        """Checks for rules which are not required due to new applications and
        removes those rules
        """
        rules = (context.session.query(RouterRule)
                 .filter_by(router_id=router_id).all())
        sorted_rules = sorted(rules, key=lambda k: k.priority)
        persist_list = []
        for hp_rule, lp_rule in itertools.combinations(sorted_rules, 2):
            # combinations('ABCD', 2) --> AB AC AD BC BD CD
            LOG.debug('\n rule_a::: %s nexthops::: %s '
                      '\n rule_b::: %s nexthops::: %s'
                      % (hp_rule, Set(hp_rule.nexthops),
                         lp_rule, Set(hp_rule.nexthops)))
            # hp_rule is the current rule - high priority rule
            # if any of the lower priority rules overlap with hp_rule, we need
            # to persist hp_rule, else remove it
            # hence do the reverse check with rule_a=lp_rule and rule_b=hp_rule
            if self._rule_a_obstructs_rule_b(rule_a=lp_rule, rule_b=hp_rule):
                LOG.debug('%s OBSTRUCTS %s' % (lp_rule, hp_rule))
                persist_list.append(hp_rule)

        persist_list.append(sorted_rules[-1])
        LOG.debug('persist rules::: %s' % Set(persist_list))
        redundant_rules = (Set(sorted_rules) - Set(persist_list))

        for del_rule in redundant_rules:
            LOG.debug('Removing redundant rule: %s' % del_rule)
            context.session.delete(del_rule)

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

    def _reset_to_router_default(self, context, router):
        tenant_id = self._get_tenant_id_for_create(context, router)
        # set default router rules
        rules = self._get_tenant_default_router_rules(tenant_id)
        # delete all existing
        (context.session.query(RouterRule)
         .filter_by(router_id=router['id']).delete())
        min_priority = MAX_PRIORITY
        for new_rule_dict in rules:
            if min_priority <= MIN_PRIORITY_DIFF:
                raise Exception("Exhausted number of rules")
            new_rule = RouterRule(
                priority=min_priority,
                router_id=router['id'],
                destination=new_rule_dict['destination'],
                source=new_rule_dict['source'],
                action=new_rule_dict['action'],
                nexthops=[NextHop(nexthop=hop)
                          for hop in new_rule_dict['nexthops']])
            context.session.add(new_rule)
            min_priority = min_priority - MIN_PRIORITY_DIFF
        return

    def _perform_compaction_and_update(self, context, router, rules):
        """Given the set of rules, generates a diff between existing and
        new rule set. Add or remove rule based on the diff.

        If new rule is covered by an existing rule, it is ignored. If it
        nullifies an existing rule, the existing rule is removed.

        If removing a rule nullifies an existing rule, the existing rule is
        removed.
        """
        LOG.debug('Update router rules::: %s', rules)
        old_rules = (context.session.query(RouterRule)
                     .filter_by(router_id=router['id']).all())
        LOG.debug('Existing router rules::: %s', old_rules)

        # reset rules
        if rules and rules[0]['priority'] == -2:
            # reset operation
            return self._reset_to_router_default(context, router)

        # delete rules
        if len(old_rules) > len(rules):
            # its a delete operation
            old_rules_dict = self._make_router_rule_list(old_rules)
            delete_rules = self._get_rule_diff(rules, old_rules_dict)

            for del_rule in delete_rules:
                LOG.debug('Removing rule: %s' % del_rule)
                (context.session.query(RouterRule)
                 .filter_by(id=del_rule['id']).delete())
            self._remove_redundant_rules(context, router_id=router['id'])
            return

        # add rules
        new_rules_list = self._get_rule_diff(old_rules, rules)
        if new_rules_list:
            new_rules_list = sorted(new_rules_list,
                                    key=lambda k: k['priority'], reverse=True)
        for new_rule_dict in new_rules_list:
            old_rules = (context.session.query(RouterRule)
                         .filter_by(router_id=router['id']).all())
            if new_rule_dict['priority'] == -1:
                # totally new rule
                LOG.debug('Adding new rule %s' % new_rule_dict)
                # trying to add a new rule with highest priority
                id_cleanup_needed, min_priority = self._min_priority(old_rules)
                if id_cleanup_needed:
                    LOG.debug('Could not get a new min_priority. Compacting '
                              'and reassigning existing priorities')
                    min_priority = self._cleanup_priority_get_min(
                        context, old_rules)
                    LOG.debug('old_rules after id cleanup %s' % old_rules)

                LOG.debug('New rule priority is %s' % min_priority)
                new_rule = RouterRule(
                        priority=min_priority,
                        router_id=router['id'],
                        destination=new_rule_dict['destination'],
                        source=new_rule_dict['source'],
                        action=new_rule_dict['action'],
                        nexthops=[NextHop(nexthop=hop)
                                  for hop in new_rule_dict['nexthops']])
            else:
                # add rule with priority specified in the input
                LOG.debug('Insert rule with specified priority: %s'
                          % new_rule_dict)
                new_rule = RouterRule(
                    priority=new_rule_dict['priority'],
                    router_id=router['id'],
                    destination=new_rule_dict['destination'],
                    source=new_rule_dict['source'],
                    action=new_rule_dict['action'],
                    nexthops=[NextHop(nexthop=hop)
                              for hop in new_rule_dict['nexthops']])
                context.session.add(new_rule)

            # common processing for new rules
            # exact opposite exists
            opp_exists, opp_rule = self._opposite_rule_exists(
                context, old_rules, new_rule)
            if opp_exists:
                # remove opposite
                LOG.debug('Removing exact opposite rule: %s' % opp_rule)
                context.session.delete(opp_rule)

            # exact same rule with lower priority
            identical_exists, identical_rule = self._identical_rule_exists(
                context, old_rules, new_rule)
            if identical_exists:
                LOG.debug('Removing identical rule: %s' % identical_rule)
                context.session.delete(identical_rule)

            # query again, since some rules may have been deleted
            old_rules = (context.session.query(RouterRule)
                         .filter_by(router_id=router['id']).all())

            # lazy flush takes care of the delete
            same_action_rules = self._get_same_action_rules(
                old_rules, new_rule.action)
            # sort same action rules with high->low priority i.e. lower number
            # first
            sorted_same_action_rules = sorted(same_action_rules,
                                              key=lambda k: k['priority'])

            # default is apply_rule
            apply_rule, rule_obj = True, new_rule
            for old_rule in sorted_same_action_rules:
                if self._rule_a_superset_rule_b(rule_a=old_rule,
                                                rule_b=new_rule):
                    apply_rule, rule_obj = False, old_rule
                    LOG.debug('Found existing superset rule: %s' % old_rule)
                    break
            if apply_rule:
                for old_rule in sorted_same_action_rules:
                    if self._rule_a_superset_rule_b(rule_a=new_rule,
                                                    rule_b=old_rule):
                        # remove old_rule
                        LOG.debug('Found existing rule, subset of new rule: %s'
                                  % old_rule)
                        context.session.delete(old_rule)
                # apply the new rule
                context.session.add(new_rule)
            else:
                reverse_action_rules = self._filter_opposite_rules(rule_obj,
                                                                   old_rules)
                for rule in reverse_action_rules:
                    if self._rule_a_obstructs_rule_b(rule_a=rule,
                                                     rule_b=rule_obj):
                        # apply new rule
                        LOG.debug('Higher priority opposite rule exists, '
                                  'applying the new rule: %s' % new_rule)
                        context.session.add(new_rule)
            # remove redundant rules
            self._remove_redundant_rules(context, router_id=router['id'])

    def _update_router_rules(self, context, router, rules):
        if len(rules) > cfg.CONF.ROUTER.max_router_rules:
            raise routerrule.RulesExhausted(
                router_id=router['id'],
                quota=cfg.CONF.ROUTER.max_router_rules)
        self._perform_compaction_and_update(context, router, rules)
        context.session.flush()

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
