# -*- coding: utf-8 -*-
# pylint: disable=dangerous-default-value,too-many-public-methods
from __future__ import absolute_import

import errno
import json
import unittest

from .. import mgr
from ..security import Module, Permission
from ..services.access_control import handle_access_control_command, \
                                      load_access_control_db, \
                                      password_hash, AccessControlDB, \
                                      SYSTEM_ROLES


class CmdException(Exception):
    def __init__(self, retcode, message):
        super(CmdException, self).__init__(message)
        self.retcode = retcode


class AccessControlTest(unittest.TestCase):
    CONFIG_KEY_DICT = {}

    @classmethod
    def mock_set_config(cls, attr, val):
        cls.CONFIG_KEY_DICT[attr] = val

    @classmethod
    def mock_get_config(cls, attr, default):
        return cls.CONFIG_KEY_DICT.get(attr, default)

    @classmethod
    def setUpClass(cls):
        mgr.set_config.side_effect = cls.mock_set_config
        mgr.get_config.side_effect = cls.mock_get_config
        mgr.set_store.side_effect = cls.mock_set_config
        mgr.get_store.side_effect = cls.mock_get_config

    def setUp(self):
        self.CONFIG_KEY_DICT.clear()
        load_access_control_db()

    @classmethod
    def exec_cmd(cls, cmd, **kwargs):
        cmd_dict = {'prefix': 'dashboard {}'.format(cmd)}
        cmd_dict.update(kwargs)
        ret, out, err = handle_access_control_command(cmd_dict)
        if ret < 0:
            raise CmdException(ret, err)
        try:
            return json.loads(out)
        except ValueError:
            return out

    def load_persistent_db(self):
        config_key = AccessControlDB.accessdb_config_key()
        self.assertIn(config_key, self.CONFIG_KEY_DICT)
        db_json = self.CONFIG_KEY_DICT[config_key]
        db = json.loads(db_json)
        return db

    def validate_persistent_role(self, rolename, modules_permissions):
        db = self.load_persistent_db()
        self.assertIn('roles', db)
        self.assertIn(rolename, db['roles'])
        self.assertEqual(db['roles'][rolename]['name'], rolename)
        self.assertDictEqual(db['roles'][rolename]['modules_permissions'],
                             modules_permissions)

    def validate_persistent_no_role(self, rolename):
        db = self.load_persistent_db()
        self.assertIn('roles', db)
        self.assertNotIn(rolename, db['roles'])

    def validate_persistent_user(self, username, roles, password=None,
                                 name=None, email=None):
        db = self.load_persistent_db()
        self.assertIn('users', db)
        self.assertIn(username, db['users'])
        self.assertEqual(db['users'][username]['username'], username)
        self.assertListEqual(db['users'][username]['roles'], roles)
        if password:
            self.assertEqual(db['users'][username]['password'], password)
        if name:
            self.assertEqual(db['users'][username]['name'], name)
        if email:
            self.assertEqual(db['users'][username]['email'], email)

    def validate_persistent_no_user(self, username):
        db = self.load_persistent_db()
        self.assertIn('users', db)
        self.assertNotIn(username, db['users'])

    def test_create_role(self):
        role = self.exec_cmd('ac-role-create', rolename='test_role')
        self.assertDictEqual(role, {'name': 'test_role',
                                    'modules_permissions': {}})
        self.validate_persistent_role('test_role', {})

    def test_create_duplicate_role(self):
        self.test_create_role()

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-create', rolename='test_role')

        self.assertEqual(ctx.exception.retcode, -errno.EEXIST)
        self.assertEqual(str(ctx.exception), "Role 'test_role' already exists")

    def test_delete_role(self):
        self.test_create_role()
        out = self.exec_cmd('ac-role-delete', rolename='test_role')
        self.assertEqual(out, "Role 'test_role' deleted")
        self.validate_persistent_no_role('test_role')

    def test_delete_nonexistent_role(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-delete', rolename='test_role')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "Role 'test_role' does not exist")

    def test_show_single_role(self):
        self.test_create_role()
        role = self.exec_cmd('ac-role-show', rolename='test_role')
        self.assertDictEqual(role, {'name': 'test_role',
                                    'modules_permissions': {}})

    def test_show_nonexistent_role(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-show', rolename='test_role')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "Role 'test_role' does not exist")

    def test_show_system_roles(self):
        roles = self.exec_cmd('ac-role-show')
        self.assertEqual(len(roles), len(SYSTEM_ROLES))
        for role in roles:
            self.assertIn(role['name'], SYSTEM_ROLES)

    def test_show_system_role(self):
        role = self.exec_cmd('ac-role-show', rolename="Read-Only")
        self.assertEqual(role['name'], 'Read-Only')

    def test_delete_system_role(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-delete', rolename='Administrator')

        self.assertEqual(ctx.exception.retcode, -errno.EPERM)
        self.assertEqual(str(ctx.exception),
                         "Cannot delete system role 'Administrator'")

    def test_add_role_module_perms(self):
        self.test_create_role()
        self.exec_cmd('ac-role-add-module-perms', rolename='test_role',
                      modulename=Module.POOL,
                      permissions=[Permission.READ, Permission.DELETE])
        role = self.exec_cmd('ac-role-show', rolename='test_role')
        self.assertDictEqual(role, {'name': 'test_role',
                                    'modules_permissions': {
                                        Module.POOL: [Permission.DELETE,
                                                      Permission.READ]
                                    }})
        self.validate_persistent_role('test_role', {
            Module.POOL: [Permission.DELETE, Permission.READ]
        })

    def test_del_role_module_perms(self):
        self.test_add_role_module_perms()
        self.exec_cmd('ac-role-add-module-perms', rolename='test_role',
                      modulename=Module.MONITOR,
                      permissions=[Permission.READ, Permission.CREATE])
        self.validate_persistent_role('test_role', {
            Module.POOL: [Permission.DELETE, Permission.READ],
            Module.MONITOR: [Permission.CREATE, Permission.READ]
        })
        self.exec_cmd('ac-role-del-module-perms', rolename='test_role',
                      modulename=Module.POOL)
        role = self.exec_cmd('ac-role-show', rolename='test_role')
        self.assertDictEqual(role, {'name': 'test_role',
                                    'modules_permissions': {
                                        Module.MONITOR: [Permission.CREATE,
                                                         Permission.READ]
                                    }})
        self.validate_persistent_role('test_role', {
            Module.MONITOR: [Permission.CREATE, Permission.READ]
        })

    def test_add_role_module_perms_nonexistent_role(self):

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-add-module-perms', rolename='test_role',
                          modulename='pool',
                          permissions=['read', 'delete'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "Role 'test_role' does not exist")

    def test_add_role_invalid_module_perms(self):
        self.test_create_role()

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-add-module-perms', rolename='test_role',
                          modulename='invalidmod',
                          permissions=['read', 'delete'])

        self.assertEqual(ctx.exception.retcode, -errno.EINVAL)
        self.assertEqual(str(ctx.exception),
                         "Module 'invalidmod' is not valid\n Possible values: "
                         "{}".format(Module.all_modules()))

    def test_add_role_module_invalid_perms(self):
        self.test_create_role()

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-add-module-perms', rolename='test_role',
                          modulename='pool', permissions=['invalidperm'])

        self.assertEqual(ctx.exception.retcode, -errno.EINVAL)
        self.assertEqual(str(ctx.exception),
                         "Permission 'invalidperm' is not valid\n Possible "
                         "values: {}".format(Permission.all_permissions()))

    def test_del_role_module_perms_nonexistent_role(self):

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-del-module-perms', rolename='test_role',
                          modulename='pool')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "Role 'test_role' does not exist")

    def test_del_role_nonexistent_module_perms(self):
        self.test_add_role_module_perms()

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-del-module-perms', rolename='test_role',
                          modulename='nonexistentmod')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception),
                         "There are no permissions for module 'nonexistentmod' "
                         "in role 'test_role'")

    def test_not_permitted_add_role_module_perms(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-add-module-perms', rolename='Read-Only',
                          modulename='pool', permissions=['read', 'delete'])

        self.assertEqual(ctx.exception.retcode, -errno.EPERM)
        self.assertEqual(str(ctx.exception),
                         "Cannot update system role 'Read-Only'")

    def test_not_permitted_del_role_module_perms(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-del-module-perms', rolename='Read-Only',
                          modulename='pool')

        self.assertEqual(ctx.exception.retcode, -errno.EPERM)
        self.assertEqual(str(ctx.exception),
                         "Cannot update system role 'Read-Only'")

    def test_create_user(self, username='admin'):
        user = self.exec_cmd('ac-user-create', username=username,
                             password='admin', name='{} User'.format(username),
                             email='{}@user.com'.format(username))

        pass_hash = password_hash('admin', user['password'])
        self.assertDictEqual(user, {
            'username': username,
            'password': pass_hash,
            'name': '{} User'.format(username),
            'email': '{}@user.com'.format(username),
            'roles': []
        })
        self.validate_persistent_user(username, [], pass_hash,
                                      '{} User'.format(username),
                                      '{}@user.com'.format(username))

    def test_delete_user(self):
        self.test_create_user()
        out = self.exec_cmd('ac-user-delete', username='admin')
        self.assertEqual(out, "User 'admin' deleted")
        users = self.exec_cmd('ac-user-show')
        self.assertEqual(len(users), 0)
        self.validate_persistent_no_user('admin')

    def test_create_duplicate_user(self):
        self.test_create_user()

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-create', username='admin', password='admin')

        self.assertEqual(ctx.exception.retcode, -errno.EEXIST)
        self.assertEqual(str(ctx.exception), "User 'admin' already exists")

    def test_delete_nonexistent_user(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-delete', username='admin')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "User 'admin' does not exist")

    def test_add_user_roles(self, username='admin',
                            roles=['Pool Manager', 'Block Manager']):
        self.test_create_user(username)
        uroles = []
        for role in roles:
            uroles.append(role)
            uroles.sort()
            user = self.exec_cmd('ac-user-add-roles', username=username,
                                 roles=[role])
            self.assertDictContainsSubset({'roles': uroles}, user)
        self.validate_persistent_user(username, uroles)

    def test_add_user_roles2(self):
        self.test_create_user()
        user = self.exec_cmd('ac-user-add-roles', username="admin",
                             roles=['Pool Manager', 'Block Manager'])
        self.assertDictContainsSubset(
            {'roles': ['Block Manager', 'Pool Manager']}, user)
        self.validate_persistent_user('admin', ['Block Manager',
                                                'Pool Manager'])

    def test_add_user_roles_not_existent_user(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-add-roles', username="admin",
                          roles=['Pool Manager', 'Block Manager'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "User 'admin' does not exist")

    def test_add_user_roles_not_existent_role(self):
        self.test_create_user()
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-add-roles', username="admin",
                          roles=['Invalid Role'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception),
                         "Role 'Invalid Role' does not exist")

    def test_set_user_roles(self):
        self.test_create_user()
        user = self.exec_cmd('ac-user-add-roles', username="admin",
                             roles=['Pool Manager'])
        self.assertDictContainsSubset(
            {'roles': ['Pool Manager']}, user)
        self.validate_persistent_user('admin', ['Pool Manager'])
        user = self.exec_cmd('ac-user-set-roles', username="admin",
                             roles=['RGW Manager', 'Block Manager'])
        self.assertDictContainsSubset(
            {'roles': ['Block Manager', 'RGW Manager']}, user)
        self.validate_persistent_user('admin', ['Block Manager',
                                                'RGW Manager'])

    def test_set_user_roles_not_existent_user(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-set-roles', username="admin",
                          roles=['Pool Manager', 'Block Manager'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "User 'admin' does not exist")

    def test_set_user_roles_not_existent_role(self):
        self.test_create_user()
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-set-roles', username="admin",
                          roles=['Invalid Role'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception),
                         "Role 'Invalid Role' does not exist")

    def test_del_user_roles(self):
        self.test_add_user_roles()
        user = self.exec_cmd('ac-user-del-roles', username="admin",
                             roles=['Pool Manager'])
        self.assertDictContainsSubset(
            {'roles': ['Block Manager']}, user)
        self.validate_persistent_user('admin', ['Block Manager'])

    def test_del_user_roles_not_existent_user(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-del-roles', username="admin",
                          roles=['Pool Manager', 'Block Manager'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "User 'admin' does not exist")

    def test_del_user_roles_not_existent_role(self):
        self.test_create_user()
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-del-roles', username="admin",
                          roles=['Invalid Role'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception),
                         "Role 'Invalid Role' does not exist")

    def test_del_user_roles_not_associated_role(self):
        self.test_create_user()
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-del-roles', username="admin",
                          roles=['RGW Manager'])

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception),
                         "Role 'RGW Manager' is not associated with user "
                         "'admin'")

    def test_show_user(self):
        self.test_add_user_roles()
        user = self.exec_cmd('ac-user-show', username='admin')
        pass_hash = password_hash('admin', user['password'])
        self.assertDictEqual(user, {
            'username': 'admin',
            'password': pass_hash,
            'name': 'admin User',
            'email': 'admin@user.com',
            'roles': ['Block Manager', 'Pool Manager']
        })

    def test_show_nonexistent_user(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-show', username='admin')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "User 'admin' does not exist")

    def test_show_all_users(self):
        self.test_add_user_roles('admin', ['Administrator'])
        self.test_add_user_roles('guest', ['Read-Only'])
        users = self.exec_cmd('ac-user-show')
        self.assertEqual(len(users), 2)
        for user in users:
            self.assertIn(user['username'], ['admin', 'guest'])

    def test_del_role_associated_with_user(self):
        self.test_create_role()
        self.test_add_user_roles('guest', ['test_role'])

        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-role-delete', rolename='test_role')

        self.assertEqual(ctx.exception.retcode, -errno.EPERM)
        self.assertEqual(str(ctx.exception),
                         "Role 'test_role' is still associated with user "
                         "'guest'")

    def test_set_user_info(self):
        self.test_create_user()
        user = self.exec_cmd('ac-user-set-info', username='admin',
                             name='Admin Name', email='admin@admin.com')
        pass_hash = password_hash('admin', user['password'])
        self.assertDictEqual(user, {
            'username': 'admin',
            'password': pass_hash,
            'name': 'Admin Name',
            'email': 'admin@admin.com',
            'roles': []
        })
        self.validate_persistent_user('admin', [], pass_hash, 'Admin Name',
                                      'admin@admin.com')

    def test_set_user_info_nonexistent_user(self):
        with self.assertRaises(CmdException) as ctx:
            self.exec_cmd('ac-user-set-info', username='admin',
                          name='Admin Name', email='admin@admin.com')

        self.assertEqual(ctx.exception.retcode, -errno.ENOENT)
        self.assertEqual(str(ctx.exception), "User 'admin' does not exist")

    def test_load_v1(self):
        self.CONFIG_KEY_DICT['accessdb_v1'] = '''
            {{
                "users": {{
                    "admin": {{
                        "username": "admin",
                        "password":
                "$2b$12$sd0Az7mm3FaJl8kN3b/xwOuztaN0sWUwC1SJqjM4wcDw/s5cmGbLK",
                        "roles": ["Block Manager", "test_role"],
                        "name": "admin User",
                        "email": "admin@user.com"
                    }}
                }},
                "roles": {{
                    "test_role": {{
                        "name": "test_role",
                        "modules_permissions": {{
                            "{}": ["{}", "{}"],
                            "{}": ["{}"]
                        }}
                    }}
                }},
                "version": 1
            }}
        '''.format(Module.ISCSI, Permission.READ, Permission.UPDATE,
                   Module.POOL, Permission.CREATE)

        load_access_control_db()
        role = self.exec_cmd('ac-role-show', rolename="test_role")
        self.assertDictEqual(role, {
            'name': 'test_role',
            'modules_permissions': {
                Module.ISCSI: [Permission.READ, Permission.UPDATE],
                Module.POOL: [Permission.CREATE]
            }
        })
        user = self.exec_cmd('ac-user-show', username="admin")
        self.assertDictEqual(user, {
            'username': 'admin',
            'password':
                "$2b$12$sd0Az7mm3FaJl8kN3b/xwOuztaN0sWUwC1SJqjM4wcDw/s5cmGbLK",
            'name': 'admin User',
            'email': 'admin@user.com',
            'roles': ['Block Manager', 'test_role']
        })

    def test_update_from_previous_version_v1(self):
        self.CONFIG_KEY_DICT['username'] = 'admin'
        self.CONFIG_KEY_DICT['password'] = \
            '$2b$12$sd0Az7mm3FaJl8kN3b/xwOuztaN0sWUwC1SJqjM4wcDw/s5cmGbLK'
        load_access_control_db()
        user = self.exec_cmd('ac-user-show', username="admin")
        self.assertDictEqual(user, {
            'username': 'admin',
            'password':
                "$2b$12$sd0Az7mm3FaJl8kN3b/xwOuztaN0sWUwC1SJqjM4wcDw/s5cmGbLK",
            'name': None,
            'email': None,
            'roles': ['Administrator']
        })
