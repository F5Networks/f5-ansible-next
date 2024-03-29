# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_files
from ansible_collections.f5networks.next.plugins.modules.cm_next_files import (
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
            device_ip='10.1.1.11',
            filename='/path/some_file.json',
            name='foobar.json',
            timeout=600
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.device_ip, '10.1.1.11')
        self.assertEqual(p.filename, '/path/some_file.json')
        self.assertEqual(p.name, 'foobar.json')
        self.assertEqual(p.timeout, (6.0, 100))

    def test_module_parameters_timeout(self):
        args1 = dict(timeout=9)
        args2 = dict(timeout=1801)
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout()

        self.assertIn(
            "Timeout value must be between 10 and 1800 seconds.",
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout()

        self.assertIn(
            "Timeout value must be between 10 and 1800 seconds.",
            err2.exception.args[0]
        )

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
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_files.F5Client')
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

    def test_upload_file(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.11',
            filename='/path/to/file/schema_v16_1.json',
            description='test file',
            name="test.json",
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        expected = ('/api/v1/spaces/default/instances/15b640fd-c4c1-434c-b294-af155005d3bd/proxy-file-upload',
                    {'description': 'test file', 'fileName':
                        {'filename': '/path/to/file/schema_v16_1.json', 'mime_type': 'application/octet-stream'},
                     'name': 'test.json'}
                    )
        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_upgrade_list_device.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_not_present.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_exists.json'))
        ]
        mm.client.plugin.send_multipart.return_value = dict(code=202, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTupleEqual(mm.client.plugin.send_multipart.call_args_list[0][0], expected)
        self.assertEqual(results['description'], 'test file')
        self.assertEqual(results['name'], 'test.json')
        self.assertEqual(results['filename'], '/path/to/file/schema_v16_1.json')
        self.assertEqual(results['device_ip'], '10.1.1.11')

    def test_upload_file_no_change(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.11',
            filename='/path/to/file/schema_v16_1.json',
            description='test file',
            name="test.json",
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_force_upload_file(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.11',
            filename='/path/to/file/schema_v16_1.json',
            description='test file',
            name="test.json",
            force=True,
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_upgrade_list_device.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_exists.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_not_present.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_exists.json'))
        ]
        mm.client.plugin.send_multipart.return_value = dict(code=202, contents={})
        mm.client.delete.return_value = dict(code=202, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            mm.client.delete.call_args_list[0][0][0],
            '/device/v1/proxy/15b640fd-c4c1-434c-b294-af155005d3bd?'
            'path=/files/110995f9-e61f-46b0-b959-491b6b62c2c7'
        )
        self.assertEqual(results['description'], 'test file')
        self.assertEqual(results['name'], 'test.json')
        self.assertEqual(results['filename'], '/path/to/file/schema_v16_1.json')
        self.assertEqual(results['device_ip'], '10.1.1.11')

    def test_delete_file(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.11',
            filename='/path/to/file/schema_v16_1.json',
            name="test.json",
            state='absent',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_upgrade_list_device.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_exists.json')),
            dict(code=200, contents=load_fixture('cm_next_files_file_not_present.json')),
        ]
        mm.client.delete.return_value = dict(code=202, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(
            mm.client.delete.call_args_list[0][0][0],
            '/device/v1/proxy/15b640fd-c4c1-434c-b294-af155005d3bd?'
            'path=/files/110995f9-e61f-46b0-b959-491b6b62c2c7'
        )

    def test_delete_file_no_change(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.11',
            filename='/path/to/file/schema_v16_1.json',
            name="test.json",
            state='absent',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        # Override methods to force specific logic in the module to happen
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_wait_for_file_timeout(self, *args):
        set_module_args(dict(
            device_hostname='big-ip-next-04.f5demo.com',
            filename='/path/foobar.tgz',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)
        mm.device_exists = Mock(return_value=True)
        mm.device_uuid = '27693e63-4f56-4eed-9e71-848360abb1c3'
        mm.client.plugin.send_multipart.return_value = dict(code=202, contents={})
        mm.client.get.return_value = (dict(code=200, contents={'_embedded': {}}))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    @patch.object(cm_next_files, 'Connection')
    @patch.object(cm_next_files.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            device_ip='127.0.0.1',
            filename='/path/to/file/schema_v16_1.json',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_files.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_files, 'Connection')
    @patch.object(cm_next_files.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            device_ip='127.0.0.1',
            filename='/path/to/file/schema_v16_1.json',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_files.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            device_hostname='baz.bar.net',
            filename="/path/foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)

        mm.client.delete.return_value = dict(code=403, contents='operation forbidden')
        mm.client.plugin.send_multipart.return_value = dict(code=500, contents='internal server error')
        mm.client.get.side_effect = [
            dict(code=400, contents='server error'),
            dict(code=401, contents='access denied'),
            dict(code=200, contents={'count': 0}),
            dict(code=200, contents=load_fixture('cm_next_files_devices.json')),
        ]

        with self.assertRaises(F5ModuleError) as err1:
            mm.file_exists()
        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.device_exists()
        self.assertIn('access denied', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.device_exists()
        self.assertIn('Specified device:', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.device_exists()
        self.assertIn('Query returned more than 1 device with the specified property:', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.create_on_device()
        self.assertIn('internal server error', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove_from_device()
        self.assertIn('operation forbidden', err6.exception.args[0])

        mm.remove_from_device = Mock(return_value=True)
        mm.file_exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err7:
            mm.remove()
        self.assertIn('File not deleted from target NEXT instance.', err7.exception.args[0])
