# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_backup_restore
from ansible_collections.f5networks.next.plugins.modules.cm_next_backup_restore import (
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
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            timeout=600
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.device_ip, '10.1.1.10')
        self.assertEqual(p.filename, 'backup_from_api.tar.gz')
        self.assertEqual(p.file_password, 'Welcome123!')
        self.assertEqual(p.timeout, (6.0, 100))

        args = dict(
            device_ip='10.1.1.10',
            file_password='Welcome123!',
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.device_ip, '10.1.1.10')
        self.assertIsNone(p.filename)
        self.assertEqual(p.file_password, 'Welcome123!')

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
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_backup_restore.F5Client')
        self.p2 = patch('time.sleep')
        self.m1 = self.p1.start()
        self.p2.start()
        self.m1.return_value = MagicMock()
        self.p3 = patch(
            'ansible_collections.f5networks.next.plugins.modules.cm_next_backup_restore.sanitize_sensitive_data'
        )
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

    def test_create_backup(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            state='backup',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_backup_restore_device.json')),
            dict(code=404, contents={}),
            dict(code=200, contents=load_fixture('cm_next_backup_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_backup_task_done.json')),
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_backup_task_started.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['filename'], 'backup_from_api.tar.gz')
        self.assertEqual(results['device_ip'], '10.1.1.10')

    def test_create_backup_no_change(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            state='backup',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=True)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_create_backup_force_on(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            state='backup',
            force='yes',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_backup_restore_device.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('cm_next_backup_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_backup_task_done.json')),
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_backup_task_started.json'))
        mm.client.delete.return_value = dict(code=204, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertTrue(mm.client.delete.called)
        self.assertEqual(results['filename'], 'backup_from_api.tar.gz')
        self.assertEqual(results['device_ip'], '10.1.1.10')

    def test_restore_backup(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            state='restore',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_backup_restore_device.json')),
            dict(code=200, contents={}),
            dict(code=200, contents=load_fixture('cm_next_backup_restore_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_backup_restore_task_done.json')),
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_backup_restore_task_started.json'))
        mm.client.delete.return_value = dict(code=204, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['filename'], 'backup_from_api.tar.gz')
        self.assertEqual(results['device_ip'], '10.1.1.10')

    def test_restore_backup_no_change(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            state='restore',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_remove_backup(self, *args):
        set_module_args(dict(
            filename='backup_from_api.tar.gz',
            state='absent',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents={}),
            dict(code=404, contents={})
        ]
        mm.client.delete.return_value = dict(code=204, contents={})

        results = mm.exec_module()

        self.assertTrue(results['changed'])

    def test_remove_backup_no_change(self, *args):
        set_module_args(dict(
            filename='backup_from_api.tar.gz',
            state='absent',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.return_value = dict(code=404, contents={})

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_wait_for_task_timeout(self, *args):
        set_module_args(dict(
            device_ip='10.1.1.10',
            filename='backup_from_api',
            file_password='Welcome123!',
            state='backup',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=False)

        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_backup_task_started.json'))
        mm.client.get.return_value = dict(code=200, contents=load_fixture('cm_next_backup_task_running.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    @patch.object(cm_next_backup_restore, 'Connection')
    @patch.object(cm_next_backup_restore.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            filename='backup_from_api',
            state='absent',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_backup_restore.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_backup_restore, 'Connection')
    @patch.object(cm_next_backup_restore.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            filename='backup_from_api',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_backup_restore.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            device_hostname='baz.bar.net',
            filename="fake.tar.gz.bz2",
            file_password='Welcome123!',
            state='backup'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.client.delete.return_value = dict(code=403, contents='operation forbidden')
        mm.client.post.side_effect = [
            dict(code=500, contents='internal server error'),
            dict(code=403, contents='operation forbidden'),
            dict(code=202, contents=load_fixture('cm_next_backup_task_started.json')),
            dict(code=202, contents=load_fixture('cm_next_backup_restore_task_started.json'))
        ]
        mm.client.get.side_effect = [
            dict(code=400, contents='server error'),
            dict(code=401, contents='access denied'),
            dict(code=200, contents={'count': 0}),
            dict(code=200, contents=load_fixture('cm_next_files_devices.json')),
            dict(code=404, contents='not found'),
            dict(code=200, contents=load_fixture('cm_next_backup_task_failed.json')),
            dict(code=200, contents=load_fixture('cm_next_backup_restore_task_failed.json'))
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

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove_from_device()
        self.assertIn('operation forbidden', err6.exception.args[0])

        mm.remove_from_device = Mock(return_value=True)
        mm.file_exists = Mock(return_value=True)

        with self.assertRaises(F5ModuleError) as err7:
            mm.remove()
        self.assertIn('Backup file not removed from CM.', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err8:
            mm._check_task_on_device('foo')
        self.assertIn('not found', err8.exception.args[0])

        with self.assertRaises(F5ModuleError) as err9:
            mm.changes.api_params = Mock(return_value={'file_name': 'fake_file'})
            mm.backup_target()
        self.assertIn('internal server error', err9.exception.args[0])

        with self.assertRaises(F5ModuleError) as err10:
            mm.restore_target()
        self.assertIn('operation forbidden', err10.exception.args[0])

        with self.assertRaises(F5ModuleError) as err11:
            mm.changes.api_params = Mock(return_value={'file_name': 'fake_file'})
            mm.backup_target()
        self.assertIn('Backup failed with the following reason', err11.exception.args[0])

        with self.assertRaises(F5ModuleError) as err12:
            mm.restore_target()
        self.assertIn('Restore failed with the following reason', err12.exception.args[0])
