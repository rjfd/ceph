# -*- coding: utf-8 -*-
from __future__ import absolute_import

import inspect


class Module(object):
    """
    List of Dashboard Security Modules.
    If you need another security module, please add it here.
    """

    GLOBAL = "global"
    HOSTS = "hosts"
    CONFIG_OPT = "config-opt"
    POOL = "pool"
    OSD = "osd"
    MONITOR = "monitor"
    RBD_IMAGE = "rbd-image"
    ISCSI = "iscsi"
    RBD_MIRRORING = "rbd-mirroring"
    RGW = "rgw"
    CEPHFS = "cephfs"
    MANAGER = "manager"

    @classmethod
    def all_modules(cls):
        return [val for mod, val in
                inspect.getmembers(cls,
                                   lambda memb: not inspect.isroutine(memb))
                if not mod.startswith('_')]

    @classmethod
    def valid_module(cls, modulename):
        return modulename in cls.all_modules()


class Permission(object):
    """
    Module permissions types
    """
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"

    @classmethod
    def all_permissions(cls):
        return [val for mod, val in
                inspect.getmembers(cls,
                                   lambda memb: not inspect.isroutine(memb))
                if not mod.startswith('_')]

    @classmethod
    def valid_permission(cls, permname):
        return permname in cls.all_permissions()
