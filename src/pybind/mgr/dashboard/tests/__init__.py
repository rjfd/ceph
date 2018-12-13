# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json

from mgr_module import CLICommand
from .. import mgr


class CmdException(Exception):
    def __init__(self, retcode, message):
        super(CmdException, self).__init__(message)
        self.retcode = retcode


def exec_dashboard_cmd(command_handler, cmd, **kwargs):
    cmd_dict = {'prefix': 'dashboard {}'.format(cmd)}
    cmd_dict.update(kwargs)
    for cli_cmd in CLICommand.COMMAND_LIST:
        if cmd_dict['prefix'] == cli_cmd.prefix:
            ret, out, err = cli_cmd.call(mgr, cmd_dict, None)
            if ret < 0:
                raise CmdException(ret, err)
            try:
                return json.loads(out)
            except ValueError:
                return out

    ret, out, err = command_handler(cmd_dict)
    if ret < 0:
        raise CmdException(ret, err)
    try:
        return json.loads(out)
    except ValueError:
        return out
