# Copyright 2016, Big Switch Networks
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

import sqlalchemy as sa
from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import l3_db
from neutron.db import model_base
from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy import orm

from bsnstacklib.plugins.bigswitch.extensions import staticroute

LOG = logging.getLogger(__name__)


def setup_db():
    if BsnRoute._TEST_TABLE_SETUP:
        return
    engine = db_api.get_engine()
    BsnRoute.metadata.create_all(engine)
    BsnRouteNextHop.metadata.create_all(engine)
    BsnRoute._TEST_TABLE_SETUP = True


def clear_db():
    if not BsnRoute._TEST_TABLE_SETUP:
        return
    engine = db_api.get_engine()
    with engine.begin() as conn:
        for table in reversed(
                model_base.BASEV2.metadata.sorted_tables):
            conn.execute(table.delete())


class BsnRoute(model_base.BASEV2):
    # TODO(wolverineav) do a proper fix for this setup and clear db hack
    _TEST_TABLE_SETUP = None
    __tablename__ = 'bsn_routes'
    id = sa.Column(sa.Integer, primary_key=True)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"))
    destination = sa.Column(sa.String(64), nullable=False, unique=True)
    nexthops = orm.relationship('BsnRouteNextHop',
                                cascade='all,delete,delete-orphan')

    class Meta(object):
        unique_together = ('router_id', 'destination')


class BsnRouteNextHop(model_base.BASEV2):
    __tablename__ = 'bsn_routenexthops'
    route_id = sa.Column(sa.Integer,
                         sa.ForeignKey('bsn_routes.id', ondelete="CASCADE"),
                         primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


class Route_db_mixin(l3_db.L3_NAT_db_mixin):
    """Mixin class to support route nexthop configuration on a router."""
    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if 'routes' in r:
                self._update_router_routes(context, router_db, r['routes'])
            updated = super(Route_db_mixin, self).update_router(
                context, id, router)
            updated['routes'] = self._get_router_routes_by_router_id(
                context, id)

        return updated

    def create_router(self, context, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = super(Route_db_mixin, self).create_router(
                context, router)
            if 'routes' in r:
                self._update_router_routes(context, router_db, r['routes'])
            else:
                LOG.debug('No routes in router')
            router_db['routes'] = self._get_router_routes_by_router_id(
                context, router_db['id'])

        return router_db

    def _get_route_diff(self, existing_routes, new_routes):
        existing_dests = set()
        for route in existing_routes:
            existing_dests.add(route.destination)

        new_dests = set()
        for route in new_routes:
            new_dests.add(route.destination)

        added = new_dests.difference(existing_dests)
        deleted = existing_dests.difference(new_dests)
        updated = existing_dests.intersection(new_dests)

        routes_added = [route for route in new_routes
                        if route.destination in added]
        routes_removed = [route for route in existing_routes
                          if route.destination in deleted]
        routes_updated = [route for route in new_routes
                          if route.destination in updated]
        return routes_added, routes_removed, routes_updated

    def _update_router_routes(self, context, router, routes):
        # TODO(wolverineav) change the limit to something else if needed
        if len(routes) > cfg.CONF.ROUTER.max_router_rules:
            raise staticroute.RoutesExhausted(
                router_id=router['id'],
                quota=cfg.CONF.ROUTER.max_router_rules)
        old_routes = (context.session.query(BsnRoute)
                      .filter_by(router_id=router['id']).all())
        # convert dict type object to DB object
        new_routes = [BsnRoute(router_id=router['id'],
                               destination=route['destination'],
                               nexthops=[BsnRouteNextHop(nexthop=hop)
                                         for hop in route['nexthops']])
                      for route in routes]
        # diff existing and new routes
        routes_added, routes_removed, routes_updated = self._get_route_diff(
            old_routes, new_routes)
        # update DB with new data
        for del_route in routes_removed:
            LOG.debug('Removing route: %s' % del_route)
            context.session.query(BsnRoute).filter_by(id=del_route.id).delete()

        for add_route in routes_added:
            LOG.debug('Adding route: %s' % add_route)
            context.session.add(add_route)

        for update_route in routes_updated:
            LOG.debug('Updating route: %s' % update_route)
            context.session.query(BsnRoute).filter_by(
                destination=update_route.destination).first().nexthops = \
                update_route.nexthops
        context.session.flush()

    def _make_route_list(self, routes):
        routelist = []
        for route in routes:
            hops = [hop['nexthop'] for hop in route['nexthops']]
            routelist.append({'id': route['id'],
                              'destination': route['destination'],
                              'nexthops': hops})
        return routelist

    def _get_router_routes_by_router_id(self, context, id):
        query = context.session.query(BsnRoute)
        router_rules = query.filter_by(router_id=id).all()
        return self._make_route_list(router_rules)

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
            router = super(Route_db_mixin, self).get_router(
                context, id, fields)
            router['routes'] = self._get_router_routes_by_router_id(
                context, id)
            return router

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with context.session.begin(subtransactions=True):
            routers = super(Route_db_mixin, self).get_routers(
                context, filters, fields, sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse)
            for router in routers:
                router['routes'] = self._get_router_routes_by_router_id(
                    context, router['id'])
            return routers

    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            routers = super(Route_db_mixin, self).get_sync_data(context,
                                                                router_ids,
                                                                active=active)
            for router in routers:
                router['routes'] = self._get_router_routes_by_router_id(
                    context, router['id'])
        return routers
