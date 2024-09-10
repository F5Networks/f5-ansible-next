# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_license
from ansible_collections.f5networks.next.plugins.modules.cm_next_license import (
    ArgumentSpec, ModuleManager
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


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_license.F5Client')
        self.p2 = patch('time.sleep')
        self.m1 = self.p1.start()
        self.p2.start()
        self.m1.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.mock_module_helper.stop()

    def test_activate_with_existing_token(self, *args):
        set_module_args(dict(
            jwt_type='existing',
            jwt_name='test_token',
            next_ips=['1.2.3.4']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        instances = load_fixture('cm_get_instances.json')
        license_status = load_fixture('cm_get_license_status.json')
        license_token = load_fixture('cm_get_license_token.json')
        license_activate = load_fixture('cm_post_license_activate.json')
        task_status = load_fixture('cm_license_task_status.json')

        mm = ModuleManager(module=module)
        mm.client.get = Mock(
            side_effect=[
                dict(code=200, contents=instances),
                dict(code=200, contents=license_token),
            ]
        )
        mm.client.post = Mock(
            side_effect=[
                dict(code=200, contents=license_status),
                dict(code=200, contents=license_activate),
                dict(code=200, contents=task_status),
            ]
        )

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 3)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_activate_with_new_token(self, *args):
        set_module_args(dict(
            jwt_type='new',
            jwt_name='test_token',
            jwt='dummy_jwt',
            next_ips=['1.2.3.4']
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        create_token = load_fixture('cm_license_create_token.json')
        license_activate = load_fixture('cm_post_license_activate.json')

        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm.wait_for_task = Mock(return_value=True)

        mm.device_ids = {'1.2.3.4': 'foo'}
        mm.license_status = {'foo': 'inactive'}

        mm.client.post = Mock(side_effect=[
            dict(code=200, contents=create_token),
            dict(code=200, contents=license_activate),
        ])

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 2)

    def test_license_deactivate(self, *args):
        set_module_args(dict(
            next_ips=['1.2.3.4'],
            state='deactivate',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.device_ids = {'1.2.3.4': 'foo'}
        mm.exists = Mock(side_effect=[True, False])

        mm.client.post = Mock(return_value={
            'code': 200,
            'contents': {'foo': {'taskId': 'bar'}}
        })

        mm.wait_for_task = Mock(return_value=True)

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)

    @patch.object(cm_next_license, 'Connection')
    @patch.object(cm_next_license.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            jwt_type='existing',
            jwt_name='test_token',
            next_ips=['1.2.3.4']
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_license.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_license, 'Connection')
    @patch.object(cm_next_license.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            jwt_type='existing',
            jwt_name='test_token',
            next_ips=['1.2.3.4']
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_license.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            next_ips=['1.2.3.4'],
            jwt_name='test_token',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        res1 = mm.absent()

        self.assertFalse(res1)

        mm.remove_from_device = Mock()
        mm.exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as res2:
            mm.absent()
        self.assertIn(
            'Failed to deactivate the BIG-IP Next instance(s).',
            res2.exception.args[0]
        )

        mm.client.get = Mock(return_value={'code': 503, 'contents': 'server error'})

        with self.assertRaises(F5ModuleError) as res3:
            mm.get_device_id()
        self.assertIn('server error', res3.exception.args[0])

        with self.assertRaises(F5ModuleError) as res4:
            mm.get_license_status()
        self.assertIn(
            'cannot get license status without device ID.',
            res4.exception.args[0]
        )

        mm.client.post = Mock(return_value={'code': 503, 'contents': 'server error'})
        mm.device_ids = dict()

        with self.assertRaises(F5ModuleError) as res5:
            mm.get_license_status()
        self.assertIn('server error', res5.exception.args[0])

        with self.assertRaises(F5ModuleError) as res6:
            mm.get_jwt_id()
        self.assertIn('server error', res6.exception.args[0])

        mm.client.get = Mock(return_value={'code': 200, 'contents': None})
        with self.assertRaises(F5ModuleError) as res7:
            mm.get_jwt_id()
        self.assertIn('No tokens are present on the CM', res7.exception.args[0])

        mm.client.get = Mock(return_value={'code': 200, 'contents': [{'nickName': 'token'}]})
        with self.assertRaises(F5ModuleError) as res8:
            mm.get_jwt_id()
        self.assertIn(
            'jwt, test_token does not exist on the CM.',
            res8.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as res9:
            mm.create_jwt()
        self.assertIn('server error', res9.exception.args[0])

        mm.client.post = Mock(return_value={'code': 200, 'contents': {}})
        with self.assertRaises(F5ModuleError) as res10:
            mm.create_jwt()
        self.assertIn('could not create a new jwt.', res10.exception.args[0])

        del mm.exists
        mm.get_device_id = Mock(return_value={'4.3.2.1': 'foo'})
        with self.assertRaises(F5ModuleError) as res11:
            mm.exists()
        self.assertIn(
            'BIG-IP Next device with IP address, 1.2.3.4, was not found on the Central Manager',
            res11.exception.args[0]
        )

        mm.get_device_id = Mock(return_value={'1.2.3.4': 'foo'})
        mm.get_license_status = Mock(return_value={'foo': 'active'})
        res12 = mm.exists()
        self.assertTrue(res12)
