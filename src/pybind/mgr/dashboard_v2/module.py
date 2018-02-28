# -*- coding: utf-8 -*-
"""
openATTIC mgr plugin (based on CherryPy)
"""
from __future__ import absolute_import

import errno
import os

import cherrypy
from mgr_module import MgrModule

from .controllers.auth import Auth
from .tools import load_controllers, json_error_page, SessionExpireAtBrowserCloseTool, \
                   NotificationQueue
from .settings import Settings, options_command_list, handle_option_command
from . import logger


# cherrypy likes to sys.exit on error.  don't let it take us down too!
# pylint: disable=W0613
def os_exit_noop(*args):
    pass


# pylint: disable=W0212
os._exit = os_exit_noop


class Module(MgrModule):
    """
    dashboard module entrypoint
    """

    COMMANDS = [
        {
            'cmd': 'dashboard set-login-credentials '
                   'name=username,type=CephString '
                   'name=password,type=CephString',
            'desc': 'Set the login credentials',
            'perm': 'w'
        }
    ]
    COMMANDS.extend(options_command_list())

    def __init__(self, *args, **kwargs):
        super(Module, self).__init__(*args, **kwargs)
        logger.logger = self._logger

    def configure_module(self, in_unittest=False):
        Settings.mgr = self  # injects module instance into Settings class

        server_addr = self.get_localized_config('server_addr', '::')
        server_port = self.get_localized_config('server_port', '8080')
        if server_addr is None:
            raise RuntimeError(
                'no server_addr configured; '
                'try "ceph config-key put mgr/{}/{}/server_addr <ip>"'
                .format(self.module_name, self.get_mgr_id()))
        self.log.info('server_addr: %s server_port: %s', server_addr,
                      server_port)

        # Initialize custom handlers.
        cherrypy.tools.authenticate = cherrypy.Tool('before_handler', Auth.check_auth)
        cherrypy.tools.session_expire_at_browser_close = SessionExpireAtBrowserCloseTool()

        # Apply the 'global' CherryPy configuration.
        config = {
            'engine.autoreload.on': False
        }
        if not in_unittest:
            config.update({
                'server.socket_host': server_addr,
                'server.socket_port': int(server_port),
                'error_page.default': json_error_page
            })
        cherrypy.config.update(config)

        current_dir = os.path.dirname(os.path.abspath(__file__))
        fe_dir = os.path.join(current_dir, 'frontend/dist')
        config = {
            '/': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': fe_dir,
                'tools.staticdir.index': 'index.html'
            }
        }

        cherrypy.tree.mount(Module.ApiRoot(self), '/api')
        cherrypy.tree.mount(Module.StaticRoot(), '/', config=config)

    def serve(self):
        self.configure_module()

        cherrypy.engine.start()
        NotificationQueue.start_queue()
        logger.info('Waiting for engine...')
        self.log.info('Waiting for engine...')
        cherrypy.engine.block()
        logger.info('Engine done')

    def shutdown(self):
        logger.info('Stopping server...')
        NotificationQueue.stop()
        cherrypy.engine.exit()
        logger.info('Stopped server')

    def handle_command(self, cmd):
        res = handle_option_command(cmd)
        if res[0] == 0:
            return res
        if cmd['prefix'] == 'dashboard set-login-credentials':
            Auth.set_login_credentials(cmd['username'], cmd['password'])
            return 0, 'Username and password updated', ''

        return (-errno.EINVAL, '', 'Command not found \'{0}\''
                .format(cmd['prefix']))

    def notify(self, notify_type, notify_id):
        NotificationQueue.new_notification(notify_type, notify_id)

    class ApiRoot(object):

        def __init__(self, mgrmod):
            self.ctrls = load_controllers(mgrmod)
            logger.debug('Loaded controllers: {}'.format(self.ctrls))
            for ctrl in self.ctrls:
                logger.info('Adding controller: {} -> /api/{}'
                            .format(ctrl.__name__, ctrl._cp_path_))
                ins = ctrl()
                setattr(Module.ApiRoot, ctrl._cp_path_, ins)

        @cherrypy.expose
        def index(self):
            tpl = """API Endpoints:<br>
            <ul>
            {lis}
            </ul>
            """
            endpoints = ['<li><a href="{}">{}</a></li>'.format(ctrl._cp_path_, ctrl.__name__) for
                         ctrl in self.ctrls]
            return tpl.format(lis='\n'.join(endpoints))

    class StaticRoot(object):
        pass
