# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time

import cherrypy

from . import ApiController, RESTController
from .. import logger
from ..services.auth import AuthManager
from ..tools import Session


@ApiController('auth', secure=False)
class Auth(RESTController):
    """
    Provide login and logout actions.

    Supported config-keys:

      | KEY             | DEFAULT | DESCR                                     |
      ------------------------------------------------------------------------|
      | session-expire  | 1200    | Session will expire after <expires>       |
      |                           | seconds without activity                  |
    """

    def create(self, username, password, stay_signed_in=False):
        now = time.time()
        if AuthManager.authenticate(username, password):
            cherrypy.session.regenerate()
            cherrypy.session[Session.USERNAME] = username
            cherrypy.session[Session.TS] = now
            cherrypy.session[Session.EXPIRE_AT_BROWSER_CLOSE] = not stay_signed_in
            logger.debug('Login successful')
            return {'username': username}

        cherrypy.response.status = 403
        logger.debug('Login failed')
        return {'detail': 'Invalid credentials'}

    def bulk_delete(self):
        logger.debug('Logout successful')
        cherrypy.session[Session.USERNAME] = None
        cherrypy.session[Session.TS] = None
