# -*- coding: utf-8 -*-
from __future__ import absolute_import

from . import ApiController, RESTController
from .. import mgr
from ..security import Module


@ApiController('host', Module.HOSTS)
class Host(RESTController):
    def list(self):
        return mgr.list_servers()
