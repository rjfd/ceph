# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .helper import DashboardTestCase


class CephfsTest(DashboardTestCase):
    CEPHFS = True

    AUTH_ROLES = ['CephFS Manager']

    @DashboardTestCase.RunAs('test', 'test', ['Block Manager'])
    def test_access_permissions(self):
        fs_id = self.fs.get_namespace_id()
        self._get("/api/cephfs/clients/{}".format(fs_id))
        self.assertStatus(403)
        self._get("/api/cephfs/data/{}/".format(fs_id))
        self.assertStatus(403)
        self._get("/api/cephfs/mds_counters/{}".format(fs_id))
        self.assertStatus(403)

    def test_cephfs_clients(self):
        fs_id = self.fs.get_namespace_id()
        data = self._get("/api/cephfs/clients/{}".format(fs_id))
        self.assertStatus(200)

        self.assertIn('status', data)
        self.assertIn('data', data)

    def test_cephfs_data(self):
        fs_id = self.fs.get_namespace_id()
        data = self._get("/api/cephfs/data/{}/".format(fs_id))
        self.assertStatus(200)

        self.assertIn('cephfs', data)
        self.assertIn('standbys', data)
        self.assertIn('versions', data)
        self.assertIsNotNone(data['cephfs'])
        self.assertIsNotNone(data['standbys'])
        self.assertIsNotNone(data['versions'])

    def test_cephfs_mds_counters(self):
        fs_id = self.fs.get_namespace_id()
        data = self._get("/api/cephfs/mds_counters/{}".format(fs_id))
        self.assertStatus(200)

        self.assertIsInstance(data, dict)
        self.assertIsNotNone(data)
