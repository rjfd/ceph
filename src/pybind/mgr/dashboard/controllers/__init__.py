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
from ..settings import Settings
from ..tools import Session, TaskManager


def ApiController(path, secure=True):
    def decorate(cls):
        cls._cp_controller_ = True
        cls._cp_path_ = path
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

    mapper.connect(ApiRoot.__name__, "{}/api".format(url_prefix),
                   controller=ApiRoot("{}/api".format(url_prefix),
                                      ctrls))
    return mapper


def json_error_page(status, message, traceback, version):
    cherrypy.response.headers['Content-Type'] = 'application/json'
    return json.dumps(dict(status=status, detail=message, traceback=traceback,
                           version=version))


class ApiRoot(object):

    _cp_config = {
        'tools.sessions.on': True,
        'tools.authenticate.on': True
    }

    def __init__(self, base_url, ctrls):
        self.base_url = base_url
        self.ctrls = ctrls

    def __call__(self):
        tpl = """API Endpoints:<br>
        <ul>
        {lis}
        </ul>
        """
        endpoints = ['<li><a href="{}/{}">{}</a></li>'
                     .format(self.base_url, ctrl._cp_path_, ctrl.__name__) for
                     ctrl in self.ctrls]
        return tpl.format(lis='\n'.join(endpoints))


def browsable_api_view(meth):
    def wrapper(self, *vpath, **kwargs):
        assert isinstance(self, BaseController)
        if not Settings.ENABLE_BROWSABLE_API:
            return meth(self, *vpath, **kwargs)
        if 'text/html' not in cherrypy.request.headers.get('Accept', ''):
            return meth(self, *vpath, **kwargs)
        if '_method' in kwargs:
            cherrypy.request.method = kwargs.pop('_method').upper()
        if '_raw' in kwargs:
            kwargs.pop('_raw')
            return meth(self, *vpath, **kwargs)

        template = """
        <html>
        <h1>Browsable API</h1>
        {docstring}
        <h2>Request</h2>
        <p>{method} {breadcrump}</p>
        <h2>Response</h2>
        <p>Status: {status_code}<p>
        <pre>{reponse_headers}</pre>
        <form action="/api/{path}/{vpath}" method="get">
        <input type="hidden" name="_raw" value="true" />
        <button type="submit">GET raw data</button>
        </form>
        <h2>Data</h2>
        <pre>{data}</pre>
        {create_form}
        <h2>Note</h2>
        <p>Please note that this API is not an official Ceph REST API to be
        used by third-party applications. It's primary purpose is to serve
        the requirements of the Ceph Dashboard and is subject to change at
        any time. Use at your own risk.</p>
        """

        create_form_template = """
        <h2>Create Form</h2>
        <form action="/api/{path}/{vpath}" method="post">
        {fields}<br>
        <input type="hidden" name="_method" value="post" />
        <button type="submit">Create</button>
        </form>
        """

        try:
            data = meth(self, *vpath, **kwargs)
        except Exception as e:  # pylint: disable=broad-except
            except_template = """
            <h2>Exception: {etype}: {tostr}</h2>
            <pre>{trace}</pre>
            Params: {kwargs}
            """
            import traceback
            tb = sys.exc_info()[2]
            cherrypy.response.headers['Content-Type'] = 'text/html'
            data = except_template.format(
                etype=e.__class__.__name__,
                tostr=str(e),
                trace='\n'.join(traceback.format_tb(tb)),
                kwargs=kwargs
            )

        if cherrypy.response.headers['Content-Type'] == 'application/json':
            data = json.dumps(json.loads(data), indent=2, sort_keys=True)

        try:
            create = getattr(self, 'create')
            f_args = RESTController._function_args(create)
            input_fields = ['{name}:<input type="text" name="{name}">'.format(name=name) for name in
                            f_args]
            create_form = create_form_template.format(
                fields='<br>'.join(input_fields),
                path=self._cp_path_,
                vpath='/'.join(vpath)
            )
        except AttributeError:
            create_form = ''

        def mk_breadcrump(elems):
            return '/'.join([
                '<a href="/{}">{}</a>'.format('/'.join(elems[0:i+1]), e)
                for i, e in enumerate(elems)
            ])

        cherrypy.response.headers['Content-Type'] = 'text/html'
        return template.format(
            docstring='<pre>{}</pre>'.format(self.__doc__) if self.__doc__ else '',
            method=cherrypy.request.method,
            path=self._cp_path_,
            vpath='/'.join(vpath),
            breadcrump=mk_breadcrump(['api', self._cp_path_] + list(vpath)),
            status_code=cherrypy.response.status,
            reponse_headers='\n'.join(
                '{}: {}'.format(k, v) for k, v in cherrypy.response.headers.items()),
            data=data,
            create_form=create_form
        )

    wrapper.exposed = True
    if hasattr(meth, '_cp_config'):
        wrapper._cp_config = meth._cp_config
    return wrapper


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


class BaseControllerMeta(type):
    def __new__(mcs, name, bases, dct):
        new_cls = type.__new__(mcs, name, bases, dct)

        for a_name, thing in new_cls.__dict__.items():
            if isinstance(thing, (types.FunctionType, types.MethodType))\
                    and getattr(thing, 'exposed', False):

                # @cherrypy.tools.json_out() is incompatible with our browsable_api_view decorator.
                cp_config = getattr(thing, '_cp_config', {})
                if not cp_config.get('tools.json_out.on', False):
                    setattr(new_cls, a_name, browsable_api_view(thing))
        return new_cls


@add_metaclass(BaseControllerMeta)
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
            if step[0] == ':':
                param = step[1:]
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
                setattr(cls, attr, wrapper)
                result.append(
                    (val._collection_method_, attr, attr, []))

        for attr, val in inspect.getmembers(cls, predicate=isfunction):
            if hasattr(val, '_resource_method_'):
                wrapper = cls._rest_request_wrapper(val, 200)
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
