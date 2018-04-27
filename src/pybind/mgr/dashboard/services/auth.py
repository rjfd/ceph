# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time

import cherrypy
from cherrypy._cpcompat import base64_decode

from .access_control import LocalAuthenticator
from .. import mgr, logger
from ..tools import Session


class AuthManager(object):
    AUTH_PROVIDER = None

    @classmethod
    def initialize(cls):
        cls.AUTH_PROVIDER = LocalAuthenticator()

    @classmethod
    def authenticate(cls, username, password):
        return cls.AUTH_PROVIDER.authenticate(username, password)

    @classmethod
    def authorize(cls, username, module, permissions):
        return cls.AUTH_PROVIDER.authorize(username, module, permissions)


class AuthManagerTool(cherrypy.Tool):
    def __init__(self):
        super(AuthManagerTool, self).__init__(
            'before_handler', self._check_authentication, priority=20)

    def _authenticate_using_auth_header(self):
        auth_header = cherrypy.request.headers.get('authorization')
        if auth_header is not None:
            scheme, params = auth_header.split(' ', 1)
            if scheme.lower() == 'basic':
                username, password = base64_decode(params).split(':', 1)
                logger.debug("Basic authentication user=%s", username)
                if AuthManager.authenticate(username, password):
                    now = time.time()
                    cherrypy.session.regenerate()
                    cherrypy.session[Session.USERNAME] = username
                    cherrypy.session[Session.TS] = now
                    cherrypy.session[Session.EXPIRE_AT_BROWSER_CLOSE] = True
                    return username
        return None

    def _check_authentication(self):
        username = cherrypy.session.get(Session.USERNAME)
        if not username:
            username = self._authenticate_using_auth_header()
            if username is None:
                logger.debug('Unauthorized access to %s',
                             cherrypy.url(relative='server'))
                cherrypy.serving.response.headers[
                    'www-authenticate'] = 'Basic realm="dashboard"'
                raise cherrypy.HTTPError(401, 'You are not authorized '
                                              'to access that resource')

        now = time.time()
        expires = float(mgr.get_config(
            'session-expire', Session.DEFAULT_EXPIRE))
        if expires > 0:
            username_ts = cherrypy.session.get(Session.TS, None)
            if username_ts and float(username_ts) < (now - expires):
                cherrypy.session[Session.USERNAME] = None
                cherrypy.session[Session.TS] = None
                logger.debug('Session expired')
                raise cherrypy.HTTPError(401,
                                         'Session expired. You are not '
                                         'authorized to access that resource')
        cherrypy.session[Session.TS] = now

        self._check_authorization(username)

    def _check_authorization(self, username):
        logger.debug("AMT: checking authorization...")
        handler = cherrypy.request.handler.callable
        controller = handler.__self__
        sec_module = getattr(controller, '_security_module', None)
        sec_perms = getattr(handler, '_security_permissions', None)
        logger.debug("AMT: checking %s access to '%s' module", sec_perms,
                     sec_module)
        if not sec_module or not sec_perms:
            logger.debug("Fail to check permission on: %s:%s", controller,
                         handler)
            raise cherrypy.HTTPError(403, "You don't have permissions to "
                                          "access that resource")

        if not AuthManager.authorize(username, sec_module, sec_perms):
            raise cherrypy.HTTPError(403, "You don't have permissions to "
                                          "access that resource")
