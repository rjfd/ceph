# -*- coding: utf-8 -*-
# pylint: disable=W0212
from __future__ import absolute_import

import collections
from datetime import datetime, timedelta
import fnmatch
from functools import wraps
import importlib
import inspect
import json
import os
import pkgutil
import sys
import time
import threading
import types  # pylint: disable=import-error

import cherrypy
from six import add_metaclass

from .. import logger
from ..exceptions import ModuleNotValid, PermissionNotValid
from ..security import Module, Permission
from ..settings import Settings
from ..tools import Session, TaskManager


def ApiController(path, security_module=None, secure=True):
    if security_module and not Module.valid_module(security_module):
        logger.debug("Invalid security module name: %s\n Possible values: %s",
                     security_module, Module.all_modules())
        raise ModuleNotValid(security_module)

    def decorate(cls):
        cls._cp_controller_ = True
        cls._cp_path_ = path
        cls._security_module = security_module
        config = {
            'tools.sessions.on': True,
            'tools.sessions.name': Session.NAME,
            'tools.session_expire_at_browser_close.on': True,
            'tools.authenticate.on': secure
        }
        if not hasattr(cls, '_cp_config'):
            cls._cp_config = {}
        cls._cp_config.update(config)
        return cls
    return decorate


def load_controllers():
    # setting sys.path properly when not running under the mgr
    controllers_dir = os.path.dirname(os.path.realpath(__file__))
    dashboard_dir = os.path.dirname(controllers_dir)
    mgr_dir = os.path.dirname(dashboard_dir)
    logger.debug("LC: controllers_dir=%s", controllers_dir)
    logger.debug("LC: dashboard_dir=%s", dashboard_dir)
    logger.debug("LC: mgr_dir=%s", mgr_dir)
    if mgr_dir not in sys.path:
        sys.path.append(mgr_dir)

    controllers = []
    mods = [mod for _, mod, _ in pkgutil.iter_modules([controllers_dir])]
    logger.debug("LC: mods=%s", mods)
    for mod_name in mods:
        mod = importlib.import_module('.controllers.{}'.format(mod_name),
                                      package='dashboard')
        for _, cls in mod.__dict__.items():
            # Controllers MUST be derived from the class BaseController.
            if inspect.isclass(cls) and issubclass(cls, BaseController) and \
                    hasattr(cls, '_cp_controller_'):
                if cls._cp_path_.startswith(':'):
                    # invalid _cp_path_ value
                    logger.error("Invalid url prefix '%s' for controller '%s'",
                                 cls._cp_path_, cls.__name__)
                    continue
                controllers.append(cls)

    return controllers


API_MAP = collections.defaultdict(list)


def generate_controller_routes(ctrl_class, mapper, base_url):
    inst = ctrl_class()
    for methods, url_suffix, action, params in ctrl_class.endpoints():
        if not url_suffix:
            name = ctrl_class.__name__
            url = "{}/{}".format(base_url, ctrl_class._cp_path_)
        else:
            name = "{}:{}".format(ctrl_class.__name__, url_suffix)
            url = "{}/{}/{}".format(base_url, ctrl_class._cp_path_, url_suffix)

        if params:
            for param in params:
                url = "{}/:{}".format(url, param)

        conditions = dict(method=methods) if methods else None

        logger.debug("Mapping [%s] to %s:%s restricted to %s",
                     url, ctrl_class.__name__, action, methods)
        API_MAP[url].append({
            'methods': methods if methods else ['get'],
            'controller': ctrl_class
        })
        mapper.connect(name, url, controller=inst, action=action,
                       conditions=conditions)

        # adding route with trailing slash
        name += "/"
        url += "/"
        mapper.connect(name, url, controller=inst, action=action,
                       conditions=conditions)


def generate_routes(url_prefix):
    mapper = cherrypy.dispatch.RoutesDispatcher()
    ctrls = load_controllers()
    for ctrl in ctrls:
        generate_controller_routes(ctrl, mapper, "{}/api".format(url_prefix))

    return mapper


def json_error_page(status, message, traceback, version):
    cherrypy.response.headers['Content-Type'] = 'application/json'
    return json.dumps(dict(status=status, detail=message, traceback=traceback,
                           version=version))


class Task(object):
    def __init__(self, name, metadata, wait_for=5.0, exception_handler=None):
        self.name = name
        if isinstance(metadata, list):
            self.metadata = dict([(e[1:-1], e) for e in metadata])
        else:
            self.metadata = metadata
        self.wait_for = wait_for
        self.exception_handler = exception_handler

    def _gen_arg_map(self, func, args, kwargs):
        # pylint: disable=deprecated-method
        arg_map = {}
        if sys.version_info > (3, 0):  # pylint: disable=no-else-return
            sig = inspect.signature(func)
            arg_list = [a for a in sig.parameters]
        else:
            sig = inspect.getargspec(func)
            arg_list = [a for a in sig.args]

        for idx, arg in enumerate(arg_list):
            if idx < len(args):
                arg_map[arg] = args[idx]
            else:
                if arg in kwargs:
                    arg_map[arg] = kwargs[arg]
            if arg in arg_map:
                arg_map[idx] = arg_map[arg]

        return arg_map

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            arg_map = self._gen_arg_map(func, args, kwargs)
            md = {}
            for k, v in self.metadata.items():
                if isinstance(v, str) and v and v[0] == '{' and v[-1] == '}':
                    param = v[1:-1]
                    try:
                        pos = int(param)
                        md[k] = arg_map[pos]
                    except ValueError:
                        md[k] = arg_map[v[1:-1]]
                else:
                    md[k] = v
            task = TaskManager.run(self.name, md, func, args, kwargs,
                                   exception_handler=self.exception_handler)
            try:
                status, value = task.wait(self.wait_for)
            except Exception as ex:
                if task.ret_value:
                    # exception was handled by task.exception_handler
                    if 'status' in task.ret_value:
                        status = task.ret_value['status']
                    else:
                        status = 500
                    cherrypy.response.status = status
                    return task.ret_value
                raise ex
            if status == TaskManager.VALUE_EXECUTING:
                cherrypy.response.status = 202
                return {'name': self.name, 'metadata': md}
            return value
        wrapper.__wrapped__ = func
        return wrapper


class BaseController(object):
    """
    Base class for all controllers providing API endpoints.
    """

    def __init__(self):
        logger.info('Initializing controller: %s -> /api/%s',
                    self.__class__.__name__, self._cp_path_)

    @classmethod
    def _parse_function_args(cls, func):
        # pylint: disable=deprecated-method
        if sys.version_info > (3, 0):  # pylint: disable=no-else-return
            sig = inspect.signature(func)
            cargs = [k for k, v in sig.parameters.items()
                     if k != 'self' and v.default is inspect.Parameter.empty and
                     (v.kind == inspect.Parameter.POSITIONAL_ONLY or
                      v.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD)]
        else:
            func = getattr(func, '__wrapped__', func)
            args = inspect.getargspec(func)
            nd = len(args.args) if not args.defaults else -len(args.defaults)
            cargs = args.args[1:nd]

        # filter out controller path params
        for idx, step in enumerate(cls._cp_path_.split('/')):
            param = None
            if step[0] == ':':
                param = step[1:]
            elif step[0] == '{' and step[-1] == '}' and ':' in step[1:-1]:
                param, _, _regex = step[1:-1].partition(':')

            if param:
                if param not in cargs:
                    raise Exception("function '{}' does not have the"
                                    " positional argument '{}' in the {} "
                                    "position".format(func, param, idx))
                cargs.remove(param)
        return cargs

    @classmethod
    def endpoints(cls):
        result = []

        def isfunction(m):
            return inspect.isfunction(m) or inspect.ismethod(m)

        for attr, val in inspect.getmembers(cls, predicate=isfunction):
            if (hasattr(val, 'exposed') and val.exposed):
                args = cls._parse_function_args(val)
                suffix = attr
                action = attr
                if attr == '__call__':
                    suffix = None
                result.append(([], suffix, action, args))
        return result


class RESTController(BaseController):
    """
    Base class for providing a RESTful interface to a resource.

    To use this class, simply derive a class from it and implement the methods
    you want to support.  The list of possible methods are:

    * list()
    * bulk_set(data)
    * create(data)
    * bulk_delete()
    * get(key)
    * set(data, key)
    * delete(key)

    Test with curl:

    curl -H "Content-Type: application/json" -X POST \
         -d '{"username":"xyz","password":"xyz"}'  http://127.0.0.1:8080/foo
    curl http://127.0.0.1:8080/foo
    curl http://127.0.0.1:8080/foo/0

    """

    # resource id parameter for using in get, set, and delete methods
    # should be overriden by subclasses.
    # to specify a composite id (two parameters) use '/'. e.g., "param1/param2".
    # If subclasses don't override this property we try to infer the structure of
    # the resourse ID.
    RESOURCE_ID = None

    _method_mapping = collections.OrderedDict([
        (('GET', False), ('list', 200)),
        (('PUT', False), ('bulk_set', 200)),
        (('PATCH', False), ('bulk_set', 200)),
        (('POST', False), ('create', 201)),
        (('DELETE', False), ('bulk_delete', 204)),
        (('GET', True), ('get', 200)),
        (('DELETE', True), ('delete', 204)),
        (('PUT', True), ('set', 200)),
        (('PATCH', True), ('set', 200))
    ])

    @classmethod
    def set_permissions(cls, func, methods):
        if 'GET' in methods:
            _set_func_permissions(func, [Permission.READ])
        if 'POST' in methods:
            _set_func_permissions(func, [Permission.CREATE])
        if 'DELETE' in methods:
            _set_func_permissions(func, [Permission.DELETE])
        if 'PUT' in methods or 'PATCH' in methods:
            _set_func_permissions(func, [Permission.UPDATE])

    @classmethod
    def endpoints(cls):
        # pylint: disable=too-many-branches

        def isfunction(m):
            return inspect.isfunction(m) or inspect.ismethod(m)

        result = []
        for attr, val in inspect.getmembers(cls, predicate=isfunction):
            if hasattr(val, 'exposed') and val.exposed and \
                    attr != '_collection' and attr != '_element':
                result.append(([], attr, attr, cls._parse_function_args(val)))

        for k, v in cls._method_mapping.items():
            func = getattr(cls, v[0], None)
            if not k[1] and func:
                if k[0] != 'PATCH':  # we already wrapped in PUT
                    wrapper = cls._rest_request_wrapper(func, v[1])
                    cls.set_permissions(wrapper, [k[0]])
                    setattr(cls, v[0], wrapper)
                else:
                    wrapper = func
                result.append(([k[0]], None, v[0], []))

        args = []
        for k, v in cls._method_mapping.items():
            func = getattr(cls, v[0], None)
            if k[1] and func:
                if k[0] != 'PATCH':  # we already wrapped in PUT
                    wrapper = cls._rest_request_wrapper(func, v[1])
                    cls.set_permissions(wrapper, [k[0]])
                    setattr(cls, v[0], wrapper)
                else:
                    wrapper = func
                if not args:
                    if cls.RESOURCE_ID is None:
                        args = cls._parse_function_args(func)
                    else:
                        args = cls.RESOURCE_ID.split('/')
                result.append(([k[0]], None, v[0], args))

        for attr, val in inspect.getmembers(cls, predicate=isfunction):
            if hasattr(val, '_collection_method_'):
                wrapper = cls._rest_request_wrapper(val, 200)
                cls.set_permissions(wrapper, val._collection_method_)
                setattr(cls, attr, wrapper)
                result.append(
                    (val._collection_method_, attr, attr, []))

        for attr, val in inspect.getmembers(cls, predicate=isfunction):
            if hasattr(val, '_resource_method_'):
                wrapper = cls._rest_request_wrapper(val, 200)
                cls.set_permissions(wrapper, val._resource_method_)
                setattr(cls, attr, wrapper)
                res_params = [":{}".format(arg) for arg in args]
                url_suffix = "{}/{}".format("/".join(res_params), attr)
                result.append(
                    (val._resource_method_, url_suffix, attr, []))

        return result

    @classmethod
    def _rest_request_wrapper(cls, func, status_code):
        def wrapper(*vpath, **params):
            method = func
            if cherrypy.request.method not in ['GET', 'DELETE']:
                method = RESTController._takes_json(method)

            method = RESTController._returns_json(method)

            cherrypy.response.status = status_code

            return method(*vpath, **params)
        return wrapper

    @staticmethod
    def _function_args(func):
        if sys.version_info > (3, 0):  # pylint: disable=no-else-return
            return list(inspect.signature(func).parameters.keys())
        else:
            return inspect.getargspec(func).args[1:]  # pylint: disable=deprecated-method

    # pylint: disable=W1505
    @staticmethod
    def _takes_json(func):
        def inner(*args, **kwargs):
            if cherrypy.request.headers.get('Content-Type',
                                            '') == 'application/x-www-form-urlencoded':
                return func(*args, **kwargs)

            content_length = int(cherrypy.request.headers['Content-Length'])
            body = cherrypy.request.body.read(content_length)
            if not body:
                return func(*args, **kwargs)

            try:
                data = json.loads(body.decode('utf-8'))
            except Exception as e:
                raise cherrypy.HTTPError(400, 'Failed to decode JSON: {}'
                                         .format(str(e)))

            kwargs.update(data.items())
            return func(*args, **kwargs)
        return inner

    @staticmethod
    def _returns_json(func):
        def inner(*args, **kwargs):
            cherrypy.response.headers['Content-Type'] = 'application/json'
            ret = func(*args, **kwargs)
            return json.dumps(ret).encode('utf8')
        return inner

    @staticmethod
    def resource(methods=None):
        if not methods:
            methods = ['GET']

        def _wrapper(func):
            func._resource_method_ = methods
            return func
        return _wrapper

    @staticmethod
    def collection(methods=None):
        if not methods:
            methods = ['GET']

        def _wrapper(func):
            func._collection_method_ = methods
            return func
        return _wrapper


# Role-based access permissions decorators

def _set_func_permissions(func, permissions):
    if not isinstance(permissions, list):
        permissions = [permissions]

    for perm in permissions:
        if not Permission.valid_permission(perm):
            logger.debug("Invalid security permission: %s\n "
                         "Possible values: %s", perm,
                         Permission.all_permissions())
            raise PermissionNotValid(perm)

    if not hasattr(func, '_security_permissions'):
        func._security_permissions = permissions
    else:
        permissions.extend(func._security_permissions)
        func._security_permissions = list(set(permissions))


def ReadPermission(func):
    _set_func_permissions(func, Permission.READ)
    return func


def CreatePermission(func):
    _set_func_permissions(func, Permission.CREATE)
    return func


def DeletePermission(func):
    _set_func_permissions(func, Permission.DELETE)
    return func


def UpdatePermission(func):
    _set_func_permissions(func, Permission.UPDATE)
    return func
