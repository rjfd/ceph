# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json

from ..services.ceph_service import CephService
from ..tools import ApiController, RESTController, AuthRequired


@ApiController('pool')
@AuthRequired()
class Pool(RESTController):

    @classmethod
    def _serialize_pool(cls, pool, attrs):
        if not attrs or not isinstance(attrs, list):
            return pool

        res = {}
        for attr in attrs:
            if attr not in pool:
                continue
            if attr == 'type':
                res[attr] = {1: 'replicated', 3: 'erasure'}[pool[attr]]
            else:
                res[attr] = pool[attr]

        # pool_name is mandatory
        res['pool_name'] = pool['pool_name']
        return res

    @staticmethod
    def _str_to_bool(var):
        if isinstance(var, bool):
            return var
        return var.lower() in ("true", "yes", "1", 1)

    def list(self, attrs=None, stats=False):
        if attrs:
            attrs = attrs.split(',')

        if self._str_to_bool(stats):
            pools = CephService.get_pool_list_with_stats()
        else:
            pools = CephService.get_pool_list()

        return [self._serialize_pool(pool, attrs) for pool in pools]

    def get(self, pool_name, attrs=None, stats=False):
        pools = self.list(attrs, stats)
        return [pool for pool in pools if pool['pool_name'] == pool_name][0]

    # pylint: disable=too-many-arguments, too-many-locals
    @RESTController.args_from_json
    def create(self, pool, pg_num, pool_type, erasure_code_profile=None, cache_mode=None,
               tier_of=None, read_tier=None, flags=None, compression_required_ratio=None,
               application_metadata=None, crush_rule=None, rule_name=None, **kwargs):
        ecp = erasure_code_profile if erasure_code_profile else None
        CephService.send_command('mon', 'osd pool create', pool=pool, pg_num=int(pg_num),
                                 pgp_num=int(pg_num), pool_type=pool_type, erasure_code_profile=ecp)

        if cache_mode:
            CephService.send_command('mon', 'osd tier cache-mode', pool=pool, mode=cache_mode)
        if tier_of:
            CephService.send_command('mon', 'osd tier add', tierpool=tier_of, pool=pool)
        if read_tier:
            CephService.send_command('mon', 'osd tier set-overlay', pool=pool,
                                     overlaypool=read_tier)
        if flags and 'ec_overwrites' in flags:
            CephService.send_command('mon', 'osd pool set', pool=pool, var='allow_ec_overwrites',
                                     val='true')
        if compression_required_ratio:
            CephService.send_command('mon', 'osd pool set', pool=pool,
                                     var='compression_required_ratio',
                                     val=str(compression_required_ratio))
        if application_metadata:
            for app in set(json.loads(application_metadata)):
                CephService.send_command('mon', 'osd pool application enable', pool=pool, app=app)
        if crush_rule:
            CephService.send_command('mon', 'osd pool set', pool=pool, var='crush_rule',
                                     val=rule_name)
        for key, value in kwargs.items():
            if type == 'replicated' and key not in \
                    ['name', 'erasure_code_profile_id'] and value is not None:
                CephService.send_command('mon', 'osd pool set', pool=pool, var=key, val=value)
            elif self.type == 'erasure' and key not in ['name', 'size', 'min_size'] \
                    and value is not None:
                CephService.send_command('mon', 'osd pool set', pool=pool, var=key, val=value)
