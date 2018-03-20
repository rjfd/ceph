# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .helper import DashboardTestCase, authenticate


class DashboardTest(DashboardTestCase):
    @classmethod
    def tearDownClass(cls):
        super(DashboardTest, cls).tearDownClass()
        cls._ceph_cmd(['osd', 'pool', 'delete', 'dashboard_pool', 'dashboard_pool',
                       '--yes-i-really-really-mean-it'])


    @authenticate
    def test_pool_list(self):
        data = self._get("/api/pool")
        self.assertStatus(200)

        cluster_pools = self.ceph_cluster.mon_manager.list_pools()
        self.assertEqual(len(cluster_pools), len(data))
        for pool in data:
            self.assertIn('pool_name', pool)
            self.assertIn('type', pool)
            self.assertIn('flags', pool)
            self.assertIn('flags_names', pool)
            self.assertNotIn('stats', pool)
            self.assertIn(pool['pool_name'], cluster_pools)

    @authenticate
    def test_pool_list_attrs(self):
        data = self._get("/api/pool?attrs=type,flags")
        self.assertStatus(200)

        cluster_pools = self.ceph_cluster.mon_manager.list_pools()
        self.assertEqual(len(cluster_pools), len(data))
        for pool in data:
            self.assertIn('pool_name', pool)
            self.assertIn('type', pool)
            self.assertIn('flags', pool)
            self.assertNotIn('flags_names', pool)
            self.assertNotIn('stats', pool)
            self.assertIn(pool['pool_name'], cluster_pools)

    @authenticate
    def test_pool_list_stats(self):
        data = self._get("/api/pool?stats=true")
        self.assertStatus(200)

        cluster_pools = self.ceph_cluster.mon_manager.list_pools()
        self.assertEqual(len(cluster_pools), len(data))
        for pool in data:
            self.assertIn('pool_name', pool)
            self.assertIn('type', pool)
            self.assertIn('flags', pool)
            self.assertIn('stats', pool)
            self.assertIn('flags_names', pool)
            self.assertIn(pool['pool_name'], cluster_pools)

    @authenticate
    def test_pool_get(self):
        cluster_pools = self.ceph_cluster.mon_manager.list_pools()
        pool = self._get("/api/pool/{}?stats=true&attrs=type,flags,stats"
                         .format(cluster_pools[0]))
        self.assertEqual(pool['pool_name'], cluster_pools[0])
        self.assertIn('type', pool)
        self.assertIn('flags', pool)
        self.assertIn('stats', pool)
        self.assertNotIn('flags_names', pool)

    @authenticate
    def test_pool_create(self):
        data = {
            'pool': 'dashboard_pool',
            'pg_num': '10',
            'pool_type': 'replicated',
            'application_metadata': '{"rbd": {}}'
        }
        self._post('/api/pool/', data)
        self.assertStatus(201)

        pool = self._get("/api/pool/dashboard_pool")
        self.assertStatus(200)
        for k, v in data.items():
            if k == 'pool_type':
                self.assertEqual(pool['type'], 1)
            elif k == 'pg_num':
                self.assertEqual(pool[k], int(v), '{}: {} != {}'.format(k, pool[k], v))
            elif k == 'application_metadata':
                self.assertEqual(pool[k], {"rbd": {}})
            elif k == 'pool':
                self.assertEqual(pool['pool_name'], v)
            else:
                self.assertEqual(pool[k], v, '{}: {} != {}'.format(k, pool[k], v))
