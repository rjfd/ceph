from __future__ import absolute_import

import time

from . import ApiController, RESTController
from .. import mgr


def _oremote(*args, **kwargs):
    return mgr.remote("dockerorch", *args, **kwargs)


def _wait(completions):
    done = False

    while done is False:
        done = _oremote("wait", completions)

        if not done:
            any_nonpersistent = False
            for c in completions:
                if c.is_read:
                    if not c.is_complete:
                        any_nonpersistent = True
                        break
                else:
                    if not c.is_persistent:
                        any_nonpersistent = True
                        break

            if any_nonpersistent:
                time.sleep(5)
            else:
                done = True


@ApiController("/nfs")
class NfsService(RESTController):
    def list(self):
        completion = _oremote("describe_service", "nfs", None)
        _wait([completion])
        res = completion.get_result()
        if res:
            return [res]
        return []

    def create(self):
        completion = _oremote("add_stateless_service", "nfs", None)
        _wait([completion])
        completion = _oremote("describe_service", "nfs", None)
        _wait([completion])
        res = completion.get_result()
        return res

    def bulk_delete(self):
        completion = _oremote("remove_stateless_service", "nfs", None)
        _wait([completion])
