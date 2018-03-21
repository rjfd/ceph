# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
import threading
import time

from mgr_module import CommandResult

from .. import mgr, logger
from ..services.ceph_service import CephService
from ..tools import ApiController, RESTController, AuthRequired, NotificationQueue, \
                    TaskManager, TaskExecutor


class SendCommand(object):
    def __init__(self, srv_type, srv_id, cmd_dict, callback):
        NotificationQueue.register(self._handler, 'command')
        self.result = CommandResult('')
        self.srv_type = srv_type
        self.srv_id = srv_id
        cmd_dict['format'] = 'json'
        for k, v in cmd_dict.items():
            if not v:
                del cmd_dict[k]
        self.cmd_dict = json.dumps(cmd_dict)
        self.tag = "send_command_{}".format(id(self))
        self.callback = callback

    def __call__(self):
        mgr.send_command(self.result, self.srv_type, self.srv_id,
                         self.cmd_dict, self.tag)

    def _handler(self, tag):
        # pylint: disable=broad-except
        if tag == self.tag:
            try:
                self.callback(self.result.wait())
            except Exception as ex:
                logger.exception("Error while calling SendCommand callback: %s",
                                 self.tag)
                logger.error("Exception: %s", ex)


class RunAsync(object):
    def __init__(self, func, args=None, kwargs=None, callback=None):
        self.func = func
        self.args = args if args else []
        self.kwargs = kwargs if kwargs else {}
        self.callback = callback
        self.thread = threading.Thread(target=self._run)

    def __call__(self):
        self.thread.start()

    def _run(self):
        self.callback(self.func(*self.args, **self.kwargs))


class PoolCreation(object):
    """
    Pool creation state machine
    """
    # pylint: disable=too-many-instance-attributes,too-many-arguments,unused-argument
    def __init__(self, pool, pg_num, pool_type, ec_profile=None,
                 cache_mode=None, tier_of=None, read_tier=None, flags=None,
                 compression_required_ratio=None, application=None,
                 crush_rule=None, opts=None, callback=None):
        self.pool = pool
        self.pg_num = pg_num
        self.pool_type = pool_type
        self.ec_profile = ec_profile
        self.cache_mode = cache_mode
        self.tier_of = tier_of
        self.read_tier = read_tier
        self.flags = flags
        self.compression_required_ratio = compression_required_ratio
        self.application = list(application) if application else None
        self.crush_rule = crush_rule
        self.opts = list(opts.items()) if opts else None
        self.callback = callback
        self.task = None

    def __call__(self):
        self._pool_create()

    def _validate_result(self, res):
        r, _, _ = res
        return r == 0

    def _pool_create(self):
        SendCommand('mon', '',
                    {'prefix': 'osd pool create',
                     'pool': self.pool,
                     'pg_num': self.pg_num,
                     'pgp_num': self.pg_num,
                     'pool_type': self.pool_type,
                     'erasure_code_profile': self.ec_profile},
                    self._set_cache_mode)()

    def _set_cache_mode(self, res):
        self.task.set_progress(10)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.cache_mode:
            self._set_tier_of(res)
            return

        SendCommand('mon', '',
                    {'prefix': 'osd tier cache-mode',
                     'pool': self.pool,
                     'mode': self.cache_mode},
                    self._set_tier_of)()

    def _set_tier_of(self, res):
        self.task.set_progress(15)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.tier_of:
            self._set_read_tier(res)
            return

        SendCommand('mon', '',
                    {'prefix': 'osd tier add',
                     'pool': self.pool,
                     'tierpool': self.tier_of},
                    self._set_read_tier)()

    def _set_read_tier(self, res):
        self.task.set_progress(20)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.read_tier:
            self._set_ec_overwrites(res)
            return

        SendCommand('mon', '',
                    {'prefix': 'osd tier set-overlay',
                     'pool': self.pool,
                     'overlaypool': self.read_tier},
                    self._set_ec_overwrites)()

    def _set_ec_overwrites(self, res):
        self.task.set_progress(25)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.flags or 'ec_overwrites' not in self.flags:
            self._set_compression_required_ratio(res)
            return

        SendCommand('mon', '',
                    {'prefix': 'osd pool set',
                     'pool': self.pool,
                     'var': 'allow_ec_overwrites',
                     'val': 'true'},
                    self._set_compression_required_ratio)()

    def _set_compression_required_ratio(self, res):
        self.task.set_progress(30)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.compression_required_ratio:
            self._set_application(res)
            return

        SendCommand('mon', '',
                    {'prefix': 'osd pool set',
                     'pool': self.pool,
                     'var': 'compression_required_ratio',
                     'val': str(self.compression_required_ratio)},
                    self._set_application)()

    def _set_application(self, res):
        self.task.set_progress(35)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.application:
            self._set_crush_rule(res)
            return

        app = self.application.pop(0)
        SendCommand('mon', '',
                    {'prefix': 'osd pool application enable',
                     'pool': self.pool,
                     'app': app},
                    self._set_application)()

    def _set_crush_rule(self, res):
        self.task.set_progress(40)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.crush_rule:
            self._set_opts(res)
            return

        SendCommand('mon', '',
                    {'prefix': 'osd pool set',
                     'pool': self.pool,
                     'var': 'crush_rule',
                     'val': self.crush_rule},
                    self._set_opts)()

    def _set_opts(self, res):
        self.task.set_progress(45)
        if not self._validate_result(res):
            self.finish(res)
            return
        if not self.opts:
            self._monitor_pg_state(res)
            return

        opt = self.opts.pop(0)
        if not opt[1]:
            self._set_opts(res)
            return
        elif self.pool_type == 'replicated' and opt[0] in ['name', 'erasure_code_profile_id']:
            self._set_opts(res)
            return
        elif self.pool_type == 'erasure' and opt[0] in ['name', 'size', 'min_size']:
            self._set_opts(res)
            return
        else:
            SendCommand('mon', '',
                        {'prefix': 'osd pool set',
                         'pool': self.pool,
                         'var': opt[0],
                         'val': opt[1]},
                        self._set_opts)()

    def _monitor_pg_state(self, res):
        if not self._validate_result(res):
            self.finish(res)
            return

        RunAsync(CephService.get_pool_info, [self.pool],
                 callback=self._check_pg_state)()

    def _check_pg_state(self, res):
        if not res or 'pg_status' not in res:
            self.finish((-1, '', "Could not get pool pg_status",))
        pg_status = res['pg_status']
        active = 0
        if 'active+clean' in pg_status:
            if pg_status['active+clean'] == self.pg_num:
                self.finish((0, 'pool {} created successfully'.format(self.pool),
                             '',))
                return
            else:
                active = pg_status['active+clean']

        progress = int(round(active * 50.0 / self.pg_num + 50))
        self.task.set_progress(progress)

        time.sleep(1.0)
        self._monitor_pg_state((0, 'pool {} info retrieved'.format(self.pool),
                                '',))

    def finish(self, res):
        self.callback(res)


class PoolCreationExecutor(TaskExecutor):
    def init(self, task):
        super(PoolCreationExecutor, self).init(task)
        task.fn.callback = self._callback
        task.fn.task = task

    def _callback(self, res):
        r, outb, outs = res
        if r != 0:
            self.finish({'r': r, 'error': 'failed (r={}, "{}")'.format(r, outs)},
                        None)
        else:
            try:
                self.finish({'r': r, 'msg': json.loads(outb)}, None)
            except Exception:  # pylint: disable=broad-except
                self.finish({'r': r, 'mgs': outb}, None)


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

    # pylint: disable=too-many-arguments, too-many-locals, unused-argument
    @RESTController.args_from_json
    def create(self, pool, pg_num, pool_type, erasure_code_profile=None, cache_mode=None,
               tier_of=None, read_tier=None, flags=None, compression_required_ratio=None,
               application_metadata=None, crush_rule=None, rule_name=None, **kwargs):
        ecp = erasure_code_profile if erasure_code_profile else None
        if application_metadata:
            application_metadata = set(json.loads(application_metadata))

        pc = PoolCreation(pool, int(pg_num), pool_type, ecp, cache_mode,
                          tier_of, read_tier, flags, compression_required_ratio,
                          application_metadata, rule_name, kwargs)

        task = TaskManager.run("osd/pool/create", {'pool_name': pool}, pc,
                               executor=PoolCreationExecutor())

        return task.wait(5.0)
