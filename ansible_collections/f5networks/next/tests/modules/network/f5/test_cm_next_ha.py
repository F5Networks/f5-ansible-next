# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_ha
from ansible_collections.f5networks.next.plugins.modules.cm_next_ha import (
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

    def test_module_parameters_timeout(self):
        args1 = dict(timeout=9)
        args2 = dict(timeout=1801)
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout()

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout()

        self.assertIn("Timeout value must be between 10 and 1800 seconds.", err1.exception.args[0])
        self.assertIn("Timeout value must be between 10 and 1800 seconds.", err2.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_ha.F5Client')
        self.p2 = patch('time.sleep')
        self.p2.start()
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p3 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_ha.sanitize_sensitive_data')
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

    def test_create_ha_instance(self, *args):
        set_module_args(dict(
            ha_name='wojciechecosyshydha',
            ha_ip='10.146.168.20',
            active_node_ip='10.146.194.143',
            standby_node_ip='10.146.194.144',
            control_plane_vlan='ha-cp-vlan',
            control_plane_vlan_tag=100,
            data_plane_vlan='ha-dp-vlan',
            data_plane_vlan_tag=101,
            active_node_data_plane_ip='10.3.0.10/16',
            active_node_control_plane_ip='10.146.168.21/16',
            standby_node_data_plane_ip='10.3.0.11/16',
            standby_node_control_plane_ip='10.146.168.22/16',
            external=dict(
                network_name='LocalTestVLAN-115',
                vlan='external-ha-vlan',
                tag=150,
                floating_ip='10.3.0.20/16',
                active_ip='10.3.0.21/16',
                standby_ip='10.3.0.22/16'
            ),
            internal=dict(
                network_name='LocalTestVLAN-114',
                vlan='internal-ha-vlan',
                tag=160,
                floating_ip='10.3.0.30/16',
                active_ip='10.3.0.31/16',
                standby_ip='10.3.0.32/16',
            )
        )
        )

        expected = load_fixture('ha_expected.json')

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=dict(count=0)),
            dict(code=200, contents=load_fixture('cm_next_ha_standby_node.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_active_node.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_task_running.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_task_done.json'))
        ]

        mm.client.post.return_value = dict(code=200, contents=load_fixture('cm_next_ha_task_started.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertDictEqual(mm.client.post.call_args[0][1], expected)

    def test_create_ha_instance_failed(self, *args):
        set_module_args(dict(
            ha_name='wojciechecosyshydha',
            ha_ip='10.146.168.20',
            active_node_ip='10.146.194.143',
            standby_node_ip='10.146.194.144',
            control_plane_vlan='ha-cp-vlan',
            control_plane_vlan_tag=100,
            data_plane_vlan='ha-dp-vlan',
            data_plane_vlan_tag=101,
            active_node_data_plane_ip='10.3.0.10/16',
            active_node_control_plane_ip='10.146.168.21/16',
            standby_node_data_plane_ip='10.3.0.11/16',
            standby_node_control_plane_ip='10.146.168.22/16',
            external=dict(
                network_name='LocalTestVLAN-115',
                vlan='external-ha-vlan',
                tag=150,
                floating_ip='10.3.0.20/16',
                active_ip='10.3.0.21/16',
                standby_ip='10.3.0.22/16'
            ),
            internal=dict(
                network_name='LocalTestVLAN-114',
                vlan='internal-ha-vlan',
                tag=160,
                floating_ip='10.3.0.30/16',
                active_ip='10.3.0.31/16',
                standby_ip='10.3.0.32/16',
            )
        )
        )

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=dict(count=0)),
            dict(code=200, contents=load_fixture('cm_next_ha_standby_node.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_active_node.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_task_failed.json'))
        ]

        mm.client.post.return_value = dict(code=200, contents=load_fixture('cm_next_ha_task_started.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('HA creation task failed with the following reason', err.exception.args[0])

    def test_wait_for_task_timeout(self, *args):
        set_module_args(dict(
            ha_name='wojciechecosyshydha',
            ha_ip='10.146.168.20',
            active_node_ip='10.146.194.143',
            standby_node_ip='10.146.194.144',
            control_plane_vlan='ha-cp-vlan',
            data_plane_vlan='ha-dp-vlan',
            active_node_data_plane_ip='10.3.0.10/16',
            active_node_control_plane_ip='10.146.168.21/16',
            standby_node_data_plane_ip='10.3.0.11/16',
            standby_node_control_plane_ip='10.146.168.22/16',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
        )

        mm = ModuleManager(module=module)

        mm.exists = Mock(return_value=False)
        mm._get_node_uuid = Mock(return_value='abc1234')

        mm.client.get.return_value = dict(code=200, contents=dict(status='running'))
        mm.client.post.return_value = dict(code=200, contents=load_fixture('cm_next_ha_task_started.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    @patch.object(cm_next_ha, 'Connection')
    @patch.object(cm_next_ha.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            ha_name='wojciechecosyshydha',
            ha_ip='10.146.168.20',
            active_node_ip='10.146.194.143',
            standby_node_ip='10.146.194.144',
            control_plane_vlan='ha-cp-vlan',
            data_plane_vlan='ha-dp-vlan',
            active_node_data_plane_ip='10.3.0.10/16',
            active_node_control_plane_ip='10.146.168.21/16',
            standby_node_data_plane_ip='10.3.0.11/16',
            standby_node_control_plane_ip='10.146.168.22/16',
            timeout=300
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_ha.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_ha, 'Connection')
    @patch.object(cm_next_ha.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            ha_name='wojciechecosyshydha',
            ha_ip='10.146.168.20',
            active_node_ip='10.146.194.143',
            standby_node_ip='10.146.194.144',
            control_plane_vlan='ha-cp-vlan',
            data_plane_vlan='ha-dp-vlan',
            active_node_data_plane_ip='10.3.0.10/16',
            active_node_control_plane_ip='10.146.168.21/16',
            standby_node_data_plane_ip='10.3.0.11/16',
            standby_node_control_plane_ip='10.146.168.22/16',
            timeout=300
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_ha.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(cm_next_ha, 'process_json', new_callable=Mock())
    def test_device_call_functions(self, m1):
        set_module_args(dict(
            ha_name='wojciechecosyshydha',
            ha_ip='10.146.194.144',
            active_node_ip='10.146.194.143',
            standby_node_ip='10.146.168.20',
            control_plane_vlan='ha-cp-vlan',
            data_plane_vlan='ha-dp-vlan',
            active_node_data_plane_ip='10.3.0.10/16',
            active_node_control_plane_ip='10.146.168.21/16',
            standby_node_data_plane_ip='10.3.0.11/16',
            standby_node_control_plane_ip='10.146.168.22/16',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=404, contents='not found'),
            dict(code=200, contents=load_fixture('cm_next_ha_standby_node.json')),
            dict(code=200, contents=load_fixture('cm_next_ha_failover_device_ip.json')),
            dict(code=200, contents=dict(count=0)),
            dict(code=200, contents=dict(count=2)),
            dict(code=500, contents='internal server error'),
            dict(code=403, contents='forbidden')
        ]

        mm.client.post.return_value = dict(code=403, contents='forbidden')

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()

        self.assertIn('not found', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.exists()

        self.assertIn('Specified HA Cluster IP address is in use by a STANDALONE instance', err2.exception.args[0])

        self.assertFalse(mm.present())

        with self.assertRaises(F5ModuleError) as err3:
            mm._get_node_uuid('foobar')

        self.assertIn('Specified node IP: foobar, is not managed by CM.', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm._get_node_uuid('foobar')

        self.assertIn('Query returned more than 1 standby node with the specified ip', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm._get_node_uuid('foobar')

        self.assertIn('internal server error', err5.exception.args[0])

        m1.return_value = {}
        mm._get_node_uuid = Mock(return_value='abcd1234')

        with self.assertRaises(F5ModuleError) as err6:
            mm.create_on_device()

        self.assertIn('forbidden', err6.exception.args[0])

        with self.assertRaises(F5ModuleError) as err7:
            mm._check_task_on_device('foobar')

        self.assertIn('forbidden', err7.exception.args[0])
