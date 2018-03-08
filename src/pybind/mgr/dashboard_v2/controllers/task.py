# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..tools import ApiController, AuthRequired, RESTController, TaskManager


@ApiController('task')
@AuthRequired()
class TaskController(RESTController):
    def list(self, namespace=None):
        ex_t, fn_t = TaskManager.list(namespace)
        return {
            'executing_tasks': [
                {
                    'namespace': t.namespace,
                    'metadata': t.metadata,
                    'begin_time': t.begin_time
                } for t in ex_t if t.begin_time],
            'finished_tasks': [
                {
                    'namespace': t.namespace,
                    'metadata': t.metadata,
                    'begin_time': t.begin_time,
                    'end_time': t.end_time,
                    'latency': t.latency,
                    'success': not t.exception,
                    'ret_value': t.ret_value,
                    'exception': t.exception
                } for t in fn_t]
        }
