# -*- coding: utf-8 -*-
from __future__ import absolute_import

from . import ApiController, RESTController
from .. import mgr
from ..security import Module
from ..services.ceph_service import CephService


class PerfCounter(RESTController):
    service_type = None  # type: str

    def get(self, service_id):
        schema_dict = mgr.get_perf_schema(self.service_type, str(service_id))
        schema = schema_dict["{}.{}".format(self.service_type, service_id)]
        counters = []

        for key, value in sorted(schema.items()):
            counter = dict()
            counter['name'] = str(key)
            counter['description'] = value['description']
            # pylint: disable=W0212
            if mgr._stattype_to_str(value['type']) == 'counter':
                counter['value'] = CephService.get_rate(
                    self.service_type, service_id, key)
                counter['unit'] = mgr._unit_to_str(value['units'])
            else:
                counter['value'] = mgr.get_latest(
                    self.service_type, service_id, key)
                counter['unit'] = ''
            counters.append(counter)

        return {
            'service': {
                'type': self.service_type,
                'id': str(service_id)
            },
            'counters': counters
        }


@ApiController('perf_counters/mds', Module.CEPHFS)
class MdsPerfCounter(PerfCounter):
    service_type = 'mds'


@ApiController('perf_counters/mon', Module.MONITOR)
class MonPerfCounter(PerfCounter):
    service_type = 'mon'


@ApiController('perf_counters/osd', Module.OSD)
class OsdPerfCounter(PerfCounter):
    service_type = 'osd'


@ApiController('perf_counters/rgw', Module.RGW)
class RgwPerfCounter(PerfCounter):
    service_type = 'rgw'


@ApiController('perf_counters/rbd-mirror', Module.RBD_MIRRORING)
class RbdMirrorPerfCounter(PerfCounter):
    service_type = 'rbd-mirror'


@ApiController('perf_counters/mgr', Module.MANAGER)
class MgrPerfCounter(PerfCounter):
    service_type = 'mgr'


@ApiController('perf_counters', Module.GLOBAL)
class PerfCounters(RESTController):
    def list(self):
        return mgr.get_all_perf_counters()
