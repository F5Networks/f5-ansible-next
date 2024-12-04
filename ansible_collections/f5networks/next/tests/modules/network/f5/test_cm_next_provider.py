# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_provider
from ansible_collections.f5networks.next.plugins.modules.cm_next_provider import (
    ModuleParameters, ApiParameters, ArgumentSpec, ModuleManager
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


class TestParameters(unittest.TestCase):
    def test_module_parameters(self):
        args = dict(
            name='ansible-rseries',
            type='rseries',
            address='192.168.1.1',
            port=8888,
            username='admin',
            password='sekrit',
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.name, 'ansible-rseries')
        self.assertEqual(p.type, 'RSERIES')
        self.assertEqual(p.host, '192.168.1.1: 8888')
        self.assertEqual(p.port, 8888)

    def test_module_parameters_port_raises(self):
        args = dict(
            port=9999999,
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.port()
        self.assertIn('Specified port number is out of valid range', err.exception.args[0])

    def test_api_parameters(self):
        args = load_fixture('load_cm_next_provider_vsphere.json')

        p = ApiParameters(params=args)

        self.assertEqual(p.host, 'dummy.host.net')
        self.assertEqual(p.username, 'admin')

    def test_api_parameters_none(self):

        p = ApiParameters(params={})

        self.assertIsNone(p.host)
        self.assertIsNone(p.username)

    def test_module_parameters_none(self):

        p = ModuleParameters(params={})

        self.assertIsNone(p.type)
        self.assertIsNone(p.host)
        self.assertIsNone(p.port)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_provider.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_provider.sanitize_sensitive_data')
        self.m2 = self.p2.start()
        self.m2.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_create_vsphere_provider(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            address='dummy.host.net',
            username='admin',
            password='test',
            state='present'
        ))

        expected = {'connection': {'authentication': {'password': 'test', 'type': 'basic', 'username': 'admin'},
                                   'host': 'dummy.host.net'}, 'name': 'ansible-vsphere', 'type': 'VSPHERE'}
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )
        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents={})
        mm.client.post.return_value = dict(code=201, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['address'], 'dummy.host.net')
        self.assertEqual(results['name'], 'ansible-vsphere')
        self.assertEqual(results['type'], 'vsphere')
        self.assertEqual(results['username'], 'admin')
        self.assertDictEqual(mm.client.post.call_args_list[0][0][1], expected)

    def test_create_rseries_provider(self, *args):
        set_module_args(dict(
            name='ansible-rseries',
            type='rseries',
            address='192.168.1.1',
            port=8888,
            username='admin',
            password='sekrit',
            state='present'
        ))

        expected = {'connection': {'authentication': {'password': 'sekrit', 'type': 'basic', 'username': 'admin'},
                                   'host': '192.168.1.1: 8888'}, 'name': 'ansible-rseries', 'type': 'RSERIES'}
        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.plugin.debug.return_value = True
        mm.client.get.return_value = dict(code=200, contents={})
        mm.client.post.return_value = dict(code=201, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['address'], '192.168.1.1')
        self.assertEqual(results['name'], 'ansible-rseries')
        self.assertEqual(results['type'], 'rseries')
        self.assertEqual(results['username'], 'admin')
        self.assertDictEqual(mm.client.post.call_args_list[0][0][1], expected)

    def test_update_provider_no_change(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            address='dummy.host.net',
            username='admin',
            password='test',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )
        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_provider_vsphere.json')),
            dict(code=200, contents=load_fixture('load_cm_next_provider_vsphere.json'))
        ]

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_update_provider_vpshere(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            username='non-admin',
            password='complicated',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_provider_vsphere.json')),
            dict(code=200, contents=load_fixture('load_cm_next_provider_vsphere.json'))
        ]
        mm.client.put.return_value = dict(code=201, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['username'], 'non-admin')

    def test_update_provider_rseries(self, *args):
        set_module_args(dict(
            name='ansible-f5os',
            type='rseries',
            username='non-admin',
            password='complicated',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_provider_rseries.json')),
            dict(code=200, contents=load_fixture('load_cm_next_provider_rseries.json'))
        ]
        mm.client.put.return_value = dict(code=201, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['username'], 'non-admin')

    def test_update_provider_force(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            password='complicated',
            force=True,
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('cm_next_provider_vsphere.json'))
        mm.client.put.return_value = dict(code=201, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_remove_vsphere_provider(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_provider_vsphere.json')),
            dict(code=200, contents={})
        ]
        mm.client.delete.return_value = dict(code=204, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_remove_rseries_provider(self, *args):
        set_module_args(dict(
            name='ansible-f5os',
            type='rseries',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_provider_rseries.json')),
            dict(code=200, contents={})
        ]
        mm.client.delete.return_value = dict(code=204, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_remove_provider_no_change(self, *args):
        set_module_args(dict(
            name='ansible-f5os',
            type='rseries',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents={})

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_provider_raises(self, *args):
        set_module_args(dict(
            name='ansible-f5os',
            type='rseries',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('cm_next_provider_rseries.json'))
        mm.client.delete.return_value = dict(code=204, contents={})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('Failed to delete the resource', err.exception.args[0])

    def test_create_provider_no_username_raises(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            address='dummy.host.net',
            password='test',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents={})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('parameter must be provided when creating a new resource', err.exception.args[0])

    def test_create_provider_no_address_raises(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            username='admin',
            password='test',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents={})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('parameter must be provided when creating a new resource', err.exception.args[0])

    def test_create_provider_no_port_raises(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='rseries',
            address='dummy.host.net',
            username='admin',
            password='test',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )

        mm = ModuleManager(module=module)
        mm.client.get.return_value = dict(code=200, contents={})

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('parameter must be provided when provider type is', err.exception.args[0])

    @patch.object(cm_next_provider, 'Connection')
    @patch.object(cm_next_provider.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            type='rseries',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_provider.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_provider, 'Connection')
    @patch.object(cm_next_provider.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            type='rseries',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_provider.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self, *args):
        set_module_args(dict(
            name='ansible-vsphere',
            type='vsphere',
            address='dummy.host.net',
            username='admin',
            password='test',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_by=self.spec.required_by
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=500, contents='internal server error'),
            dict(code=200, contents={"_embedded": {"providers": [1, 2]}}),
            dict(code=404, contents='not found'),
        ]

        mm.client.post.return_value = dict(code=500, contents='internal server error')
        mm.client.put.return_value = dict(code=401, contents='unauthorized')
        mm.client.delete.return_value = dict(code=403, contents='method not allowed')

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('internal server', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exists()
        self.assertIn('Query returned more than 1', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.create_on_device()
        self.assertIn('internal server', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.update_on_device()
        self.assertIn('unauthorized', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.remove_from_device()
        self.assertIn('not allowed', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.read_current_from_device()
        self.assertIn('not found', err6.exception.args[0])
