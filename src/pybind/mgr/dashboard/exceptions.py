# -*- coding: utf-8 -*-
from __future__ import absolute_import


class NoCredentialsException(Exception):
    def __init__(self):
        super(NoCredentialsException, self).__init__(
            'No RGW credentials found, '
            'please consult the documentation on how to enable RGW for '
            'the dashboard.')


# access control module exceptions
class RoleAlreadyExists(Exception):
    def __init__(self, name):
        super(RoleAlreadyExists, self).__init__(
            "Role '{}' already exists".format(name))


class RoleDoesNotExist(Exception):
    def __init__(self, name):
        super(RoleDoesNotExist, self).__init__(
            "Role '{}' does not exist".format(name))


class ModuleNotValid(Exception):
    def __init__(self, name):
        super(ModuleNotValid, self).__init__(
            "Module '{}' is not valid".format(name))


class PermissionNotValid(Exception):
    def __init__(self, name):
        super(PermissionNotValid, self).__init__(
            "Permission '{}' is not valid".format(name))


class RoleIsAssociatedWithUser(Exception):
    def __init__(self, rolename, username):
        super(RoleIsAssociatedWithUser, self).__init__(
            "Role '{}' is still associated with user '{}'"
            .format(rolename, username))


class UserAlreadyExists(Exception):
    def __init__(self, name):
        super(UserAlreadyExists, self).__init__(
            "User '{}' already exists".format(name))


class UserDoesNotExist(Exception):
    def __init__(self, name):
        super(UserDoesNotExist, self).__init__(
            "User '{}' does not exist".format(name))


class ModuleNotInRole(Exception):
    def __init__(self, modulename, rolename):
        super(ModuleNotInRole, self).__init__(
            "There are no permissions for module '{}' in role '{}'"
            .format(modulename, rolename))


class RoleNotInUser(Exception):
    def __init__(self, rolename, username):
        super(RoleNotInUser, self).__init__(
            "Role '{}' is not associated with user '{}'"
            .format(rolename, username))
