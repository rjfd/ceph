# -*- coding: utf-8 -*-
# pylint: disable=unused-argument
# pylint: disable=too-many-statements,too-many-branches
from __future__ import absolute_import

import math
from functools import partial
from datetime import datetime

import cherrypy
import six
import time

import rbd

from . import ApiController, RESTController, Task, UpdatePermission, DeletePermission
from .. import mgr
from ..security import Scope
from ..services.ceph_service import CephService
from ..tools import ViewCache, str_to_bool
from ..services.exception import handle_rados_error, handle_rbd_error, \
    serialize_dashboard_exception


# pylint: disable=not-callable
def NfsTask(name, metadata, wait_for):
    def composed_decorator(func):
        return Task("nfs/{}".format(name), metadata, wait_for,
                    partial(serialize_dashboard_exception, include_http_status=True))(func)
    return composed_decorator


@ApiController('/nfs', Scope.NFS)
class Nfs(RESTController):

    RESOURCE_ID = "host_name/export_id"

    nfs_number = 2
    nfs_list = [
            {
                "id": "bluestore-test-3.oa.suse.de:1",
                "exportId": "1",
                "host": "bluestore-test-3.oa.suse.de",
                "path": "/",
                "pseudo": "/cephfs/",
                "tag": None,
                "accessType": "RW",
                "squash": "Root",
                "protocols": ["NFSv3", "NFSv4"],
                "transports": ["UDP", "TCP"],
                "fsal": "CEPH",
                "rgwUserId": None,
                "clientBlocks": []
            },
            {
                "id": "bluestore-test-3.oa.suse.de:2",
                "exportId": "2",
                "host": "bluestore-test-3.oa.suse.de",
                "path": "/",
                "pseudo": "/admin",
                "tag": None,
                "accessType": "RW",
                "squash": "Root",
                "protocols": ["NFSv3",
                "NFSv4"],
                "transports": ["UDP",
                "TCP"],
                "fsal": "RGW",
                "rgwUserId": "admin",
                "clientBlocks": []},
            {
                "id": "bluestore-test-2.oa.suse.de:1",
                "exportId": "1",
                "host": "bluestore-test-2.oa.suse.de",
                "path": "/",
                "pseudo": "/cephfs/",
                "tag": None,
                "accessType": "RW",
                "squash": "Root",
                "protocols": ["NFSv3",
                "NFSv4"],
                "transports": ["UDP",
                "TCP"],
                "fsal": "CEPH",
                "rgwUserId": None,
                "clientBlocks": []
            },
            {
                "id": "bluestore-test-2.oa.suse.de:2",
                "exportId": "2",
                "host": "bluestore-test-2.oa.suse.de",
                "path": "/",
                "pseudo": "/admin",
                "tag": None,
                "accessType": "RW",
                "squash": "Root",
                "protocols": ["NFSv3",
                "NFSv4"],
                "transports": ["UDP",
                "TCP"],
                "fsal": "RGW",
                "rgwUserId": "admin",
                "clientBlocks": []
            }
        ]

    @ViewCache()
    def _nfs_list(self):
        result = {'status': 0, 'value': self.nfs_list}
        return result

    def list(self):
        # return self._nfs_list()
        result = {'status': 0, 'value': self.nfs_list}
        return result

    def get(self, host_name, export_id):
        for x in self.nfs_list:
            if x['host']==host_name and x['exportId']==export_id:
                return x

        raise cherrypy.HTTPError(404)

    @NfsTask('create', {'host_name': '{host}'}, 2.0)
    def create(self, clientBlocks, fsal, transports, protocols, squash,
                accessType, pseudo, path, host, tag=None, rgwUserId=None):
        time.sleep(10)

        nfs = {
            "host": host,
            "path": path,
            "pseudo": pseudo,
            "tag": tag,
            "accessType": accessType,
            "squash": squash,
            "protocols":protocols,
            "transports": transports,
            "fsal": fsal,
            "rgwUserId": rgwUserId,
            "clientBlocks": clientBlocks
        }

        nfs["exportId"] = str(self.nfs_number)
        nfs["id"] = host + ":" + str(self.nfs_number)
        self.nfs_number += 1

        self.nfs_list.append(nfs)

        return True

    @NfsTask('delete', ['{host_name}', '{export_id}'], 2.0)
    def delete(self, host_name, export_id):
        time.sleep(5)
        i = 0
        for x in self.nfs_list:
            if x['host']==host_name and x['exportId']==export_id:
                self.nfs_list.pop(i)
                return True
            i = i + 1

        return False

    @NfsTask('edit', ['{host_name}', '{export_id}'], 4.0)
    def set(self, host_name, export_id, clientBlocks, exportId, fsal, id,
                transports, protocols, squash, accessType, pseudo, path, host,
                tag=None, rgwUserId=None):
        time.sleep(5)

        index = 0
        for x in self.nfs_list:
            if x['host']==host_name and x['exportId']==export_id:
                break
            index += 1

        nfs = {
            "id": self.nfs_list[index]["id"],
            "exportId": str(exportId),
            "host": host,
            "path": path,
            "pseudo": pseudo,
            "tag": tag,
            "accessType": accessType,
            "squash": squash,
            "protocols":protocols,
            "transports": transports,
            "fsal": fsal,
            "rgwUserId": rgwUserId,
            "clientBlocks": clientBlocks
        }

        self.nfs_list[index] = nfs

        return True

    @NfsTask('copy',
             {'src_pool_name': '{host_name}',
              'src_image_name': '{export_id}',
              'dest_pool_name': '{host}',
              'dest_image_name': '{exportId}'}, 2.0)
    @RESTController.Resource('POST')
    def copy(self, host_name, export_id, clientBlocks, exportId, fsal, id,
                transports, protocols, squash, accessType, pseudo, path, host,
                tag=None, rgwUserId=None):
        time.sleep(5)

        nfs = {
            "host": host,
            "path": path,
            "pseudo": pseudo,
            "tag": tag,
            "accessType": accessType,
            "squash": squash,
            "protocols":protocols,
            "transports": transports,
            "fsal": fsal,
            "rgwUserId": rgwUserId,
            "clientBlocks": clientBlocks
        }

        nfs["exportId"] = str(self.nfs_number)
        nfs["id"] = host + ":" + str(self.nfs_number)
        self.nfs_number += 1

        self.nfs_list.append(nfs)

        return True
    @RESTController.Collection('GET')
    def lsdir(self):
        return ['/foo', '/bar']

    @RESTController.Collection('GET')
    def buckets(self):
        return ['foo', 'bar']

    @RESTController.Collection('GET')
    def hosts(self):
        return [
            'bluestore-test-3.oa.suse.de',
            'bluestore-test-2.oa.suse.de'
        ]

    @RESTController.Collection('GET')
    def fsals(self):
        return ['CEPH', 'RGW']


@ApiController('/nfs/host', Scope.NFS)
class NfsHost(RESTController):
    RESOURCE_ID = "host_name"

    status_data = {
        'bluestore-test-3.oa.suse.de': {
            "active": True,
            "exports": [
                { "active": True, "message": None, "export_id": 1 },
                { "active": True, "message": None, "export_id": 2 }
            ]
        },
        'bluestore-test-2.oa.suse.de': {
            "active": True,
            "exports": [
                { "active": True, "message": None, "export_id": 1 },
                { "active": True, "message": None, "export_id": 2 }
            ]
        }
    }

    def list(self):
        return [
            'bluestore-test-3.oa.suse.de',
            'bluestore-test-2.oa.suse.de'
        ]

    @RESTController.Collection('GET')
    def status(self):
        return self.status_data

    @NfsTask('host/start', ['{host_name}'], 2.0)
    @RESTController.Resource('PUT')
    @UpdatePermission
    def start(self, host_name):
        time.sleep(5)
        self.status_data[host_name]["active"] = True

    @NfsTask('host/stop', ['{host_name}'], 2.0)
    @RESTController.Resource('PUT')
    @UpdatePermission
    def stop(self, host_name):
        time.sleep(5)
        self.status_data[host_name]["active"] = False
