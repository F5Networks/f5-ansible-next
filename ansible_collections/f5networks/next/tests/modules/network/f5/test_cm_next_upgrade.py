# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_upgrade
from ansible_collections.f5networks.next.plugins.modules.cm_next_upgrade import (
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
            filename='BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz',
            sig_filename='BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz.512.sig',
            timeout=600
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.device_ip, '10.1.1.11')
        self.assertEqual(p.filename, 'BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz')
        self.assertEqual(p.sig_filename, 'BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz.512.sig')
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


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_upgrade.F5Client')
        self.m1 = self.p1.start()
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.m1.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_upgrade.sanitize_sensitive_data')
        self.m3 = self.p3.start()
        self.m3.return_value = Mock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.p2.stop()
        self.p3.stop()
        self.mock_module_helper.stop()

    def test_upgrade_by_device_ip(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.11',
            filename='BIG-IP-Next-0.14.0.tgz',
            sig_filename='BIG-IP-Next-0.14.0.tgz.512.sig',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        expected = {'image_name': '263bf3bc-18aa-4616-9004-09b2ee8f2b4b-6f5f95cc-b137-489d-80c8-21fde1dbfce4',
                    'signature_name': 'f64b2e2c-c385-401e-8444-83487ddab07f-4bd1457d-c3fe-46ed-8563-a1a9398938ed',
                    'upgrade_type': 've'}
        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_upgrade_list_device.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_files_on_device.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_done.json'))
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_upgrade_start.json'))
        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['version'], '0.14.0')
        self.assertDictEqual(mm.client.post.call_args[0][1], expected)
        self.assertEqual(
            mm.client.get.call_args_list[0][0][0], "/device/v1/inventory?filter=address+eq+'10.1.1.11'"
        )
        self.assertEqual(
            mm.client.get.call_args_list[1][0][0], '/device/v1/proxy/15b640fd-c4c1-434c-b294-af155005d3bd?path=/files'
        )
        self.assertEqual(
            mm.client.get.call_args_list[2][0][0],
            "/device/v1/upgrade-tasks?filter=id+eq+'db3e1e62-1013-40fc-b938-89044c805ee9'"
        )

    def test_upgrade_by_device_hostname(self, *args):
        set_module_args(dict(
            device_hostname='big-ip-next-04.f5demo.com',
            filename='BIG-IP-Next-0.14.0.tgz',
            sig_filename='BIG-IP-Next-0.14.0.tgz.512.sig',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        expected = {'image_name': '263bf3bc-18aa-4616-9004-09b2ee8f2b4b-6f5f95cc-b137-489d-80c8-21fde1dbfce4',
                    'signature_name': 'f64b2e2c-c385-401e-8444-83487ddab07f-4bd1457d-c3fe-46ed-8563-a1a9398938ed',
                    'upgrade_type': 've'}

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_upgrade_list_device.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_files_on_device.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_done.json'))
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_upgrade_start.json'))
        results = mm.exec_module()
        self.assertTrue(results['changed'])
        self.assertEqual(results['version'], '0.14.0')
        self.assertDictEqual(mm.client.post.call_args[0][1], expected)
        self.assertEqual(
            mm.client.get.call_args_list[0][0][0], "/device/v1/inventory?filter=hostname+eq+'big-ip-next-04.f5demo.com'"
        )
        self.assertEqual(
            mm.client.get.call_args_list[1][0][0], '/device/v1/proxy/15b640fd-c4c1-434c-b294-af155005d3bd?path=/files'
        )
        self.assertEqual(
            mm.client.get.call_args_list[2][0][0],
            "/device/v1/upgrade-tasks?filter=id+eq+'db3e1e62-1013-40fc-b938-89044c805ee9'"
        )

    def test_upgrade_failed(self, *args):
        set_module_args(dict(
            device_hostname='big-ip-next-04.f5demo.com',
            filename='BIG-IP-Next-0.14.0.tgz',
            sig_filename='BIG-IP-Next-0.14.0.tgz.512.sig',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        expected = {'image_name': '263bf3bc-18aa-4616-9004-09b2ee8f2b4b-6f5f95cc-b137-489d-80c8-21fde1dbfce4',
                    'signature_name': 'f64b2e2c-c385-401e-8444-83487ddab07f-4bd1457d-c3fe-46ed-8563-a1a9398938ed',
                    'upgrade_type': 've'}

        # Override methods to force specific logic in the module to happen
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_upgrade_list_device.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_files_on_device.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_upgrade_task_failed.json'))
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_upgrade_start.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()
        self.assertIn('Upgrade failed with the following reason', err.exception.args[0])
        self.assertDictEqual(mm.client.post.call_args[0][1], expected)
        self.assertEqual(
            mm.client.get.call_args_list[0][0][0], "/device/v1/inventory?filter=hostname+eq+'big-ip-next-04.f5demo.com'"
        )
        self.assertEqual(
            mm.client.get.call_args_list[1][0][0], '/device/v1/proxy/15b640fd-c4c1-434c-b294-af155005d3bd?path=/files'
        )
        self.assertEqual(
            mm.client.get.call_args_list[2][0][0],
            "/device/v1/upgrade-tasks?filter=id+eq+'db3e1e62-1013-40fc-b938-89044c805ee9'"
        )

    def test_wait_for_task_timeout(self, *args):
        set_module_args(dict(
            device_hostname='big-ip-next-04.f5demo.com',
            filename='foobar.tgz',
            sig_filename='foobar.sig',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        files = [
            {"fileName": "foobar.tgz", "uri": "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/263bf3bc"},
            {"fileName": "foobar.sig", "uri": "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/f64b2e2c"}
        ]

        mm = ModuleManager(module=module)
        mm.can_be_upgraded = Mock(return_value=True)
        mm.list_files_on_target_device = Mock(return_value=files)
        mm.client.get.return_value = dict(code=200, contents=load_fixture('cm_next_upgrade_task_running.json'))
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_upgrade_start.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    @patch.object(cm_next_upgrade, 'Connection')
    @patch.object(cm_next_upgrade.ModuleManager, 'exec_module',
                  Mock(return_value={'changed': False})
                  )
    def test_main_function_success(self, *args):
        set_module_args(dict(
            filename='foo.tar',
            sig_filename='bar.sig',
            device_hostname='baz.net.bar'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_upgrade.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_upgrade, 'Connection')
    @patch.object(cm_next_upgrade.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            filename='foo.tar',
            sig_filename='bar.sig',
            device_hostname='baz.net.bar'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_upgrade.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_remaining_methods(self):
        set_module_args(dict(
            device_hostname='big-ip-next-04.f5demo.com',
            filename='foobar.tgz',
            sig_filename='foobar.sig',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        with self.assertRaises(F5ModuleError) as err1:
            files = [
                {"fileName": "barfoo.tgz", "uri": "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/263bf3bc"},
                {"fileName": "foobar.sig", "uri": "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/f64b2e2c"}
            ]
            mm.list_files_on_target_device = Mock(return_value=files)
            mm.get_files_ids()
        self.assertIn('The given filename', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            files = [
                {"fileName": "foobar.tgz", "uri": "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/263bf3bc"},
                {"fileName": "barfoo.sig", "uri": "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/f64b2e2c"}
            ]
            mm.list_files_on_target_device = Mock(return_value=files)
            mm.get_files_ids()
        self.assertIn('The given sig_filename', err2.exception.args[0])

        mm.client.get.side_effect = [
            dict(code=200, contents=dict(count=0)),
            dict(code=200, contents=dict(count=2)),
            dict(code=504, contents='gateway error')
        ]

        with self.assertRaises(F5ModuleError) as err3:
            mm.device_exists()
        self.assertIn('Specified device:', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.device_exists()
        self.assertIn('Query returned more than 1 device with the specified property:', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.device_exists()
        self.assertIn('gateway error', err5.exception.args[0])

        set_module_args(dict(
            device_hostname='big-ip-next-04.f5demo.com',
            filename='foobar.tgz',
            sig_filename='foobar.sig',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=dict(count=0)),
            dict(code=403, contents='forbidden'),
            dict(code=404, contents='not found'),
        ]

        with self.assertRaises(F5ModuleError) as err6:
            mm.list_files_on_target_device()
        self.assertIn('No files found on upgrade target, upgrade aborted.', err6.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            mm.list_files_on_target_device()
        self.assertIn('forbidden', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err8:
            mm._check_task_on_device('foo')
        self.assertIn('not found', err8.exception.args[0])

        mm.client.post.return_value = dict(code=504, contents='gateway error')

        with self.assertRaises(F5ModuleError) as err9:
            mm.get_files_ids = Mock(return_value=('foo', 'bar'))
            mm.upgrade_target()
        self.assertIn('gateway error', err9.exception.args[0])

        mm.device_exists = Mock(return_value=False)
        self.assertFalse(mm.present())
