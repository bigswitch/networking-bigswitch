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

import sqlalchemy as sa

from bsnstacklib.plugins.bigswitch.i18n import _
from bsnstacklib.plugins.bigswitch.i18n import _LI
from bsnstacklib.plugins.bigswitch.i18n import _LW
from neutron.common import exceptions
from neutron.db import model_base
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_db.sqlalchemy import session
from oslo_log import log as logging
from sqlalchemy.types import Enum

LOG = logging.getLogger(__name__)


def setup_db():
    '''Helper to register models for unit tests'''
    if NameCacheHandler._FACADE is None:
        NameCacheHandler._FACADE = session.EngineFacade.from_config(
            cfg.CONF, sqlite_fk=True)
    TenantCache.metadata.create_all(NameCacheHandler._FACADE.get_engine())
    TenantObjCache.metadata.create_all(NameCacheHandler._FACADE.get_engine())


def clear_db():
    '''Helper to unregister models and clear engine in unit tests'''
    if not NameCacheHandler._FACADE:
        return
    TenantCache.metadata.drop_all(NameCacheHandler._FACADE.get_engine())
    TenantObjCache.metadata.drop_all(NameCacheHandler._FACADE.get_engine())
    NameCacheHandler._FACADE = None


class ObjectNameNotUnique(exceptions.NeutronException):
    message = _("Object of type %(obj_type)s and name %(name_nospace)s "
                "already exists on the BCF controller.")
    status = None

    def __init__(self, **kwargs):
        self.obj_type = kwargs.get('obj_type')
        self.name_nospace = kwargs.get('name_nospace')
        super(ObjectNameNotUnique, self).__init__(**kwargs)


class NamecacheCreateException(exceptions.NeutronException):
    message = _("Exception when creating namecache object of type %(obj_type)s"
                " and name %(name_nospace)s : %(nc_exc)s")
    status = None

    def __init__(self, **kwargs):
        self.obj_type = kwargs.get('obj_type')
        self.name_nospace = kwargs.get('name_nospace')
        self.nc_exc = kwargs.get('nc_exc')
        super(NamecacheCreateException, self).__init__(**kwargs)


class NamecacheDeleteException(exceptions.NeutronException):
    message = _("Exception when deleting namecache object of type %(obj_type)s"
                " and ID %(name_nospace)s : %(nc_exc)s")
    status = None

    def __init__(self, **kwargs):
        self.obj_type = kwargs.get('obj_type')
        self.id = kwargs.get('id')
        self.nc_exc = kwargs.get('nc_exc')
        super(NamecacheDeleteException, self).__init__(**kwargs)


class NamecacheMissingException(exceptions.NeutronException):
    message = _("Missing namecache mapping for %(obj_type)s named: "
                "%(obj_name)s.")
    status = None

    def __init__(self, **kwargs):
        self.obj_type = kwargs.get('obj_type')
        self.obj_name = kwargs.get('obj_name')
        super(NamecacheMissingException, self).__init__(**kwargs)


class ObjTypeEnum(Enum):
    network = "network"
    router = "router"
    security_group = "security_group"
    tenant = "tenant"


class TenantCache(model_base.BASEV2):
    '''
    This table is used to cache names of tenants with space in their name.
    '''
    __tablename__ = 'bsn_tenant_namecache'
    id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    # name and name_nospace both aren't unique, but the composite obj with
    # the whole row is unique
    name = sa.Column(sa.String(255), nullable=False, unique=True)
    name_nospace = sa.Column(sa.String(255), nullable=False, unique=True)


class TenantObjCache(model_base.BASEV2):
    '''
    This table is used to cache names of tenant related objects that has space
    in its name.
    '''
    __tablename__ = 'bsn_tenant_obj_namecache'
    # this is an enum specifying the type of object being renamed
    obj_type = sa.Column(ObjTypeEnum(name="obj_type"), nullable=False,
                         primary_key=True)
    # uuid for the given obj type
    id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    tenant_id = sa.Column(sa.String(36),
                          sa.ForeignKey('bsn_tenant_namecache.id',
                                        ondelete="CASCADE"),
                          primary_key=True)
    # name and name_nospace both aren't unique, but the composite obj with
    # the whole row is unique
    name = sa.Column(sa.String(255), nullable=False, unique=False)
    name_nospace = sa.Column(sa.String(255), nullable=False, unique=False)

    class Meta(object):
        unique_together = ('obj_type', 'tenant_id', 'name_nospace')


class NameCacheHandler(object):
    '''
    A wrapper object to keep track of the session between the read
    and the update operations.

    This class needs an SQL engine completely independent of the main
    neutron connection so rollbacks from consistency hash operations don't
    affect the parent sessions.

    Similar to HashHandler for ConsistencyDb
    '''
    _FACADE = None

    def __init__(self):
        # create a session for accessing the namecache objects from the DB
        if NameCacheHandler._FACADE is None:
            NameCacheHandler._FACADE = session.EngineFacade.from_config(
                cfg.CONF, sqlite_fk=True)
        self.session = (NameCacheHandler._FACADE
                        .get_session(autocommit=True, expire_on_commit=False))

    def create_tenant(self, id, name):
        name_nospace = name.replace(' ', '_')
        tenantcache_obj = TenantCache(id=id, name=name,
                                      name_nospace=name_nospace)
        try:
            with self.session.begin(subtransactions=True):
                LOG.info(_LI("Creating tenant namecache with %(tenant_obj)s"),
                         {'tenant_obj': str(tenantcache_obj)})
                self.session.add(tenantcache_obj)
                return tenantcache_obj
        except db_exc.DBDuplicateEntry:
            '''
            create_tenant can be called multiple times for the same tenant,
            during the periodic tenant cache sync with the controller. hence,
            we handle it correctly.
            '''
            tenantcache_obj = self.get_tenant(tenant_id=id)
            if tenantcache_obj.name == name:
                LOG.info(_LI("Found existing tenant in namecache with "
                             "%(tenant_obj)s"),
                         {'tenant_obj': str(tenantcache_obj)})
                return tenantcache_obj
            else:
                raise ObjectNameNotUnique(
                    obj_type=ObjTypeEnum.tenant,
                    name_nospace=tenantcache_obj.name_nospace)
        except Exception as e:
            raise NamecacheCreateException(
                obj_type=ObjTypeEnum.tenant,
                name_nospace=tenantcache_obj.name_nospace,
                nc_exc=str(e))

    def create_tenant_subobj(self, obj_type, obj):
        name_nospace = obj['name'].replace(' ', '_')
        namecache_obj = TenantObjCache(
            obj_type=obj_type, tenant_id=obj['tenant_id'],
            id=obj['id'], name=obj['name'], name_nospace=name_nospace)
        try:
            with self.session.begin(subtransactions=True):
                LOG.info(_LI("Creating %(obj_type)s in namecache "
                             "with %(cache_obj)s"),
                         {'obj_type': obj_type,
                          'cache_obj': str(namecache_obj)})
                self.session.add(namecache_obj)
                return namecache_obj
        except db_exc.DBDuplicateEntry:
            namecache_obj = self.get_tenant_subobj(obj_type, obj['id'])
            if namecache_obj.name == obj['name']:
                LOG.info(_LI("Found existing %(obj_type)s in namecache with "
                             "%(cache_obj)s"),
                         {'obj_type': obj_type,
                          'cache_obj': str(namecache_obj)})
                return namecache_obj
            else:
                raise ObjectNameNotUnique(
                    obj_type=obj_type, name_nospace=namecache_obj.name_nospace)
        except Exception as e:
            raise NamecacheCreateException(
                obj_type=obj_type, name_nospace=namecache_obj.name_nospace,
                nc_exc=str(e))

    def get_tenant(self, tenant_id):
        # try and return the mapping if available:
        with self.session.begin(subtransactions=True):
            try:
                result = (self.session.query(TenantCache)
                          .filter_by(id=tenant_id)
                          .first())
                LOG.debug("returning a tenant namecache object %s" % result)
                return result
            except Exception as e:
                LOG.warning(_LW("Tenant not found in namecache %(tenant_id)s "
                                "due to exception %(exc)s"),
                            {'tenant_id': tenant_id, 'exc': str(e)})
                return None

    def get_all_tenants(self):
        with self.session.begin(subtransactions=True):
            try:
                result = self.session.query(TenantCache).all()
                tenant_dict = {}
                for tenant in result:
                    tenant_dict[tenant.id] = tenant.name_nospace
                LOG.debug("Returning all tenants from namecache %s" %
                          str(tenant_dict))
                return tenant_dict
            except Exception as e:
                LOG.warning(_LW("Exception when getting all tenants from "
                                "namecache %(exc)s"), {'exc': str(e)})
                return {}

    def get_tenant_subobj(self, obj_type, obj_id):
        # try and return the mapping if available:
        with self.session.begin(subtransactions=True):
            try:
                result = (self.session.query(TenantObjCache)
                          .filter_by(obj_type=obj_type,
                                     id=obj_id)
                          .first())
                LOG.debug("returning a tenant subobject namecache object %s" %
                          result)
                return result
            except Exception as e:
                LOG.warning(_LW("%(obj_type)s not found in namecache "
                                "%(obj_id)s due to exception %(exc)s"),
                            {'obj_type': obj_type, 'obj_id': obj_id,
                             'exc': str(e)})
                return None

    def get_all_tenant_subobj(self):
        with self.session.begin(subtransactions=True):
            all_subobj_dict = {
                ObjTypeEnum.network: {},
                ObjTypeEnum.router: {},
                ObjTypeEnum.security_group: {},
            }
            try:
                result = self.session.query(TenantObjCache).all()

                for obj in result:
                    if obj.tenant_id not in all_subobj_dict[obj.obj_type]:
                        all_subobj_dict[obj.obj_type] = {
                            obj.tenant_id: {
                                obj.id: obj.name_nospace
                            }
                        }
                    else:
                        all_subobj_dict[obj.obj_type][obj.tenant_id][obj.id]\
                            = obj.name_nospace

                return all_subobj_dict
            except Exception as e:
                LOG.warning(_LW("Exception when getting all tenant subobj from"
                                " namecache %(exc)s"), {'exc': str(e)})
                return all_subobj_dict

    def delete_tenant(self, tenant_id):
        with self.session.begin(subtransactions=True):
            try:
                tenantcache_obj = self.get_tenant(tenant_id)
                if not tenantcache_obj:
                    # object does not exist, return
                    LOG.info(_LI("Tenant %(id)s not found in namecache. "
                                 "Nothing to delete."), {'id': tenant_id})
                    return
                self.session.delete(tenantcache_obj)
            except Exception as e:
                raise NamecacheDeleteException(obj_type=ObjTypeEnum.tenant,
                                               id=tenant_id,
                                               nc_exc=str(e))

    def delete_tenant_subobj(self, obj_type, obj_id):
        with self.session.begin(subtransactions=True):
            try:
                namecache_obj = self.get_tenant_subobj(obj_type, obj_id)
                if not namecache_obj:
                    # object does not exist, return
                    LOG.info(_LI("%(obj_type)s %(id)s not found in namecache. "
                                 "Nothing to delete."),
                             {'obj_type': obj_type, 'id': obj_id})
                    return
                self.session.delete(namecache_obj)
            except Exception as e:
                raise NamecacheDeleteException(obj_type=obj_type, id=obj_id,
                                               nc_exc=str(e))
