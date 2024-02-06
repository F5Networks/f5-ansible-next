# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_ha_failover
from ansible_collections.f5networks.next.plugins.modules.cm_next_ha_failover import (
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
            ha_ip='10.1.1.11',
            ha_hostname='foo.bar.net',
            active_unit_ip='11.11.1.11',
            active_unit_hostname='unit1.foo.bar.net',
            timeout=600
        )
        p = ModuleParameters(params=args)

        self.assertEqual(p.ha_ip, '10.1.1.11')
        self.assertEqual(p.ha_hostname, 'foo.bar.net')
        self.assertEqual(p.active_unit_ip, '11.11.1.11')
        self.assertEqual(p.active_unit_hostname, 'unit1.foo.bar.net')
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
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_ha_failover.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.p3 = patch(
            'ansible_collections.f5networks.next.plugins.modules.cm_next_ha_failover.sanitize_sensitive_data'
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

    def test_failover_by_ha_ip(self, *args):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.74.173',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_ha_failover_device_ip.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_health.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_task_done.json')),
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_ha_failover_task_start.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['active_unit_ip'], '10.145.74.173')

    def test_failover_by_ha_hostname(self, *args):
        set_module_args(dict(
            ha_hostname='myHA',
            active_unit_hostname='mbip-2.instances.f5net.local',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_ha_failover_device_hostname.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_health.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_task_done.json')),
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_ha_failover_task_start.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['active_unit_hostname'], 'mbip-2.instances.f5net.local')

    def test_failover_no_change(self, *args):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.80.175',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_ha_failover_device_ip.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_health.json'))
        ]

        results = mm.exec_module()

        self.assertFalse(results['changed'])

    def test_failover_failed(self, *args):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.74.173',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_ha_failover_device_ip.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_health.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_task_failed.json')),
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_ha_failover_task_start.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn("Failover job did not succeed on BIG-IP Next HA instance", err.exception.args[0])

    def test_wait_for_task_timeout(self, *args):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.74.173',
            timeout=600
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_one_of=self.spec.required_one_of
        )
        mm = ModuleManager(module=module)
        mm._check_task_on_device = Mock(return_value=load_fixture('cm_next_ha_failover_task_running.json'))
        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_ha_failover_device_ip.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_health.json'))
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_ha_failover_task_start.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    @patch.object(cm_next_ha_failover, 'Connection')
    @patch.object(cm_next_ha_failover.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.74.173'
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_ha_failover.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_ha_failover, 'Connection')
    @patch.object(cm_next_ha_failover.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.74.173'
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_ha_failover.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            ha_ip='10.145.66.121',
            active_unit_ip='10.145.74.173'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_one_of=self.spec.required_one_of,
            mutually_exclusive=self.spec.mutually_exclusive
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=400, contents='server error'),
            dict(code=200, contents={'count': 0}),
            dict(code=200, contents=load_fixture('cm_next_files_devices.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_wrong_device.json')),
            dict(code=401, contents='access denied'),
            dict(code=403, contents='forbidden'),
        ]

        mm.client.post.return_value = dict(code=404, contents='not found')

        with self.assertRaises(F5ModuleError) as err1:
            mm.ha_exists()
        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.ha_exists()
        self.assertIn('Specified HA instance:', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.ha_exists()
        self.assertIn('Query returned more than 1 HA instance', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.ha_exists()
        self.assertIn('does not seem to be running in HA mode.', err5.exception.args[0])

        with self.assertRaises(F5ModuleError) as err6:
            mm.read_current_from_device()
        self.assertIn('access denied', err6.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            mm._check_task_on_device('foo')
        self.assertIn('forbidden', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err8:
            mm.update_on_device()
        self.assertIn('not found', err8.exception.args[0])
