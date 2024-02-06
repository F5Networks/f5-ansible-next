# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_device_info
from ansible_collections.f5networks.next.plugins.modules.cm_device_info import (
    ArgumentSpec, ModuleManager, Parameters
)
from ansible_collections.f5networks.next.plugins.module_utils.common import F5ModuleError

from ansible_collections.f5networks.next.tests.compat import unittest
from ansible_collections.f5networks.next.tests.compat.mock import (
    Mock, patch, MagicMock
)
from ansible_collections.f5networks.next.tests.modules.utils import (
    set_module_args, fail_json, exit_json, AnsibleExitJson, AnsibleFailJson
)


fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)

    if path in fixture_data:
        return fixture_data[path]

    with open(path) as f:
        data = f.read()

    try:
        data = json.loads(data)
    except Exception:
        pass

    fixture_data[path] = data
    return data


class TestBaseParameters(unittest.TestCase):
    def test_gather_subset(self):
        args = dict(
            gather_subset=['users'],
        )
        p = Parameters(params=args)
        assert p.gather_subset == ['users']

    def test_gather_subset_cast_to_list(self):
        args = dict(
            gather_subset='users',
        )
        p = Parameters(params=args)
        assert p.gather_subset == ['users']

    def test_gather_subset_raises(self):
        args = dict(
            gather_subset=tuple('users'),
        )
        p = Parameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.gather_subset()

        self.assertIn('must be a list', err.exception.args[0])


class TestMainManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.mock_module_helper.stop()

    def test_module_manager_execution(self):
        set_module_args(dict(
            gather_subset=['files', 'all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=dict(fake_output='some data'))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(results, {'fake_output': 'some data', 'queried': True})

    def test_module_manager_no_query(self):
        set_module_args(dict(
            gather_subset=['!users', 'managed-devices']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=dict())

        results = mm.exec_module()

        self.assertFalse(results['queried'])

    def test_module_manager_no_specific_module_manager(self):
        set_module_args(dict(
            gather_subset=['!all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=None)

        self.assertFalse(mm.get_manager('foobar'))

        results = mm.exec_module()

        self.assertFalse(results['queried'])

    def test_module_manager_invalid_subset_options(self):
        set_module_args(dict(
            gather_subset=['!all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)
        mm.execute_managers = Mock(return_value=None)

        results = mm.exec_module()

        self.assertFalse(results['queried'])

    def test_execute_managers(self):
        set_module_args(dict(
            gather_subset=['all']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        fake_manager = Mock(return_value=Mock())
        fake_manager.exec_module.return_value = dict(response='none')
        managers = list()
        managers.append(fake_manager)
        results = mm.execute_managers(managers)

        self.assertDictEqual(results, {'response': 'none'})

    @patch.object(cm_device_info, 'Connection')
    @patch.object(cm_device_info.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            gather_subset=['all']
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_device_info.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_device_info, 'Connection')
    @patch.object(cm_device_info.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            gather_subset=['all']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_device_info.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])


class TestFilesModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.sanitize_sensitive_data')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_files_facts(self, *args):
        set_module_args(dict(
            gather_subset=['files']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        fm = mm.get_manager('files')
        fm.client.get.return_value = dict(code=200, contents=load_fixture('cm_device_info_files.json'))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(
            results['files'][0],
            {'description': 'file to test stuff', 'file_name': 'random_file', 'file_size': 24269,
             'hash': '5553857c29abf3733e4a95076b069e2590a51ce4f0f9536bc15080c62dcc1720',
             'id': '1b1d07f3-3cd1-4326-be5e-683031f4870f', 'updated': '2023-09-05T12:45:04.871517Z'}
        )

    def test_get_files_facts_read_empty(self, *args):
        set_module_args(dict(
            gather_subset=['files']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        fm = mm.get_manager('files')
        fm.client.get.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['files'])

    def test_get_files_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['files']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        fm = mm.get_manager('files')
        fm.client.get.return_value = dict(code=500, contents='server error')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])


class TestManagedDevicesModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.sanitize_sensitive_data')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_managed_devices_facts(self, *args):
        set_module_args(dict(
            gather_subset=['managed-devices']
        ))

        expected = {'address': '10.1.1.10', 'hostname': 'big-ip-next-03.f5demo.com', 'mode': 'STANDALONE',
                    'id': '91247525-c243-4ab3-8d17-f2af50da7a7e', 'version': '20.0.0-2.94.0+0.0.26',
                    'port': 5443,
                    'health': {'status': 'HEALTHY', 'node_count': 1,
                               'nodes': [{'address': '10.1.1.10', 'port': 5443,
                                          'hostname': 'big-ip-next-03.f5demo.com',
                                          'version': '20.0.0-2.94.0+0.0.26', 'state': 'STANDALONE'}]}, 'files': []
                    }

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        dm = mm.get_manager('managed-devices')
        dm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_device_info_managed_devices.json')),
            dict(code=200, contents=load_fixture('cm_device_info_device_health_1.json')),
            dict(code=200, contents=load_fixture('cm_device_info_device_health_2.json')),
            dict(code=200, contents=load_fixture('cm_device_info_device_files.json')),
            dict(code=200, contents=load_fixture('cm_device_info_device_health_3.json')),
            dict(code=200, contents={})
        ]

        results = mm.exec_module()
        self.assertTrue(results['queried'])
        self.assertDictEqual(results['managed_devices'][0], expected)

    def test_get_managed_devices_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['managed-devices']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        dm = mm.get_manager('managed-devices')
        dm.client.get.return_value = dict(code=500, contents='server error')

        with self.assertRaises(F5ModuleError) as err:
            dm.read_collection_from_device()

        self.assertIn('server error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            dm.read_device_health_status('foo')

        self.assertIn('server error', err.exception.args[0])

        with self.assertRaises(F5ModuleError) as err:
            dm.list_device_files('foo')

        self.assertIn('server error', err.exception.args[0])

    def test_get_managed_devices_read_empty(self, *args):
        set_module_args(dict(
            gather_subset=['managed-devices']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        fm = mm.get_manager('managed-devices')
        fm.client.get.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['managed_devices'])


class TestUsersModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.sanitize_sensitive_data')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_users_facts(self, *args):
        set_module_args(dict(
            gather_subset=['users']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        um = mm.get_manager('users')
        um.client.get.return_value = dict(code=200, contents=load_fixture('cm_device_info_users.json'))

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(
            results['users'][0],
            {'change_password': False, 'id': '1be671f0-e34c-47fb-a505-1dd672a8bbf7', 'username': 'admin'}
        )
        self.assertDictEqual(
            results['users'][1],
            {'change_password': True, 'email': '', 'id': 'f59f8e8d-6f12-434b-80e3-47bbeea889aa', 'username': 'test_api'}
        )

    def test_get_users_facts_read_empty(self, *args):
        set_module_args(dict(
            gather_subset=['users']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        um = mm.get_manager('users')
        um.client.get.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['users'])

    def test_get_users_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['users']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        fm = mm.get_manager('users')
        fm.client.get.return_value = dict(code=500, contents='server error')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])


class TestProvidersModuleManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_device_info.sanitize_sensitive_data')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()

    def test_get_providers_facts(self, *args):
        set_module_args(dict(
            gather_subset=['providers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        pm = mm.get_manager('providers')
        pm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_device_info_vsphere_providers.json')),
            dict(code=200, contents=load_fixture('cm_device_info_f5os_providers.json')),
        ]

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertDictEqual(
            results['providers'][0],
            {'id': 'ee582f64-176f-4c9e-8685-dff05031bf0a',
             'name': 'ansible-vsphere', 'type': 'VSPHERE', 'username': 'admin'}
        )
        self.assertDictEqual(
            results['providers'][1],
            {'id': 'e2f21bcf-4687-4d47-86ee-d593b84aa8a1',
             'name': 'ansible-f5os', 'type': 'RSERIES', 'username': 'admin'}
        )

        self.assertDictEqual(
            results['providers'][2],
            {'id': 'aa9f20ee-6dbe-4ba4-b020-01411506b98f',
             'name': 'ansible-f5os2', 'type': 'VELOS', 'username': 'admin'}
        )

    def test_get_providers_facts_read_empty(self, *args):
        set_module_args(dict(
            gather_subset=['providers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        pm = mm.get_manager('providers')
        pm.client.get.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertTrue(results['queried'])
        self.assertFalse(results['providers'])

    def test_get_users_facts_raises(self, *args):
        set_module_args(dict(
            gather_subset=['providers']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        # Override methods to force specific logic in the module to happen
        mm = ModuleManager(module=module)
        pm = mm.get_manager('providers')
        pm.client.get.return_value = dict(code=500, contents='server error')

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('server error', err.exception.args[0])
