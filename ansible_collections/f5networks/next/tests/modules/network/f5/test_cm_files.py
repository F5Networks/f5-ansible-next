# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_files
from ansible_collections.f5networks.next.plugins.modules.cm_files import (
    ModuleParameters, ArgumentSpec, ModuleManager
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
            filename='/path/some_file.json',
            name='foobar.json'
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.filename, '/path/some_file.json')
        self.assertEqual(p.name, 'foobar.json')

    def test_module_parameters_name(self):
        args = dict(
            filename='/path/some_file.json',
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.filename, '/path/some_file.json')
        self.assertEqual(p.name, 'some_file.json')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_files.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.mock_module_helper.stop()

    def test_upload_file(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            description='test file',
            name="simple_test.json"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        expected = ('/api/system/v1/files',
                    {'content': {'filename': '/path/to/file/schema_v16_1.json',
                                 'mime_type': 'application/octet-stream'}, 'description': 'test file',
                     'file_name': 'simple_test.json'}
                    )
        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [

            dict(code=200, contents=load_fixture('cm_files_file_not_present.json')),
            dict(code=200, contents=load_fixture('cm_files_file_exists.json'))
        ]
        mm.client.plugin.send_multipart.return_value = dict(code=202, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTupleEqual(mm.client.plugin.send_multipart.call_args_list[0][0], expected)
        self.assertEqual(results['description'], 'test file')
        self.assertEqual(results['name'], 'simple_test.json')
        self.assertEqual(results['filename'], '/path/to/file/schema_v16_1.json')

    def test_upload_file_no_change(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            description='test file',
            name="simple_test.json"
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_force_upload_file(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            description='test file',
            name="simple_test.json",
            force=True
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_files_file_exists.json')),
            dict(code=200, contents=load_fixture('cm_files_file_not_present.json'))
        ]
        mm.client.plugin.send_multipart.return_value = dict(code=202, contents={})
        mm.client.delete.return_value = dict(code=204, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            mm.client.delete.call_args_list[0][0][0],
            '/system/v1/files/ee2724fd-afd6-45e8-8a1c-3f9cba7577b9'
        )
        self.assertEqual(results['description'], 'test file')
        self.assertEqual(results['name'], 'simple_test.json')
        self.assertEqual(results['filename'], '/path/to/file/schema_v16_1.json')

    def test_delete_file(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            name="simple_test.json",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_files_file_exists.json')),
            dict(code=200, contents=load_fixture('cm_files_file_not_present.json')),
        ]
        mm.client.delete.return_value = dict(code=202, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            mm.client.delete.call_args_list[0][0][0],
            '/system/v1/files/ee2724fd-afd6-45e8-8a1c-3f9cba7577b9'
        )

    def test_delete_file_no_change(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            name="simple_test.json",
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    @patch.object(cm_files, 'Connection')
    @patch.object(cm_files.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_files.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_files, 'Connection')
    @patch.object(cm_files.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            filename='/path/to/file/schema_v16_1.json',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_files.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            filename="/path/foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=400, contents='server error'),
            dict(code=200, contents={'_embedded': {'count': 0}})
        ]
        mm.client.plugin.send_multipart.return_value = dict(code=500, contents='internal server error')
        mm.client.delete.return_value = dict(code=403, contents='operation forbidden')

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        self.assertFalse(mm.exists())

        with self.assertRaises(F5ModuleError) as err2:
            mm.create_on_device()
        self.assertIn('internal server error', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove_from_device()
        self.assertIn('operation forbidden', err6.exception.args[0])

        mm.remove_from_device = Mock(return_value=True)
        mm.exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err7:
            mm.remove()
        self.assertIn('File not deleted from CM.', err7.exception.args[0])
