# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_deploy_f5os
from ansible_collections.f5networks.next.plugins.modules.cm_next_deploy_f5os import (
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
            state='deploy',
            provider=dict(
                provider_name='vCenterDemo',
                type='rseries',
                image_name='BIG-IP-Next-20.0.1-2.139.10-0.0.136-VM'
            ),
            instance=dict(
                instance_hostname='demoVM01.lab.local',
                cpus=8,
                disk_size=40,
                vlans=[21, 22, 23, 24],
                mgmt_address='172.16.1.1/24',
                mgmt_gateway='172.16.1.254',
                mgmt_user='admin-cm',
                mgmt_password='s3KrI!T',
                ha_dp_vlan_name='dp-demo-ha',
                ha_cp_vlan_name='cp-demo-ha',
                ha_dp_vlan_tag=23,
                ha_cp_vlan_tag=24,
                external_network_name='DemoNet123',
                external_vlan_name='ExtDemoVlan',
                external_vlan_tag=21,
                external_ip_address='192.168.1.1/24',
                internal_vlan_name='IntDemoVlan',
                internal_vlan_tag=22,
                internal_ip_address='192.168.2.1/24'
            )
        )

        p = ModuleParameters(params=args)

        self.assertEqual(p.provider_name, 'vCenterDemo')
        self.assertEqual(p.provider_type, 'RSERIES')
        self.assertEqual(p.image_name, 'BIG-IP-Next-20.0.1-2.139.10-0.0.136-VM')
        self.assertEqual(p.instance_hostname, 'demoVM01.lab.local')
        self.assertEqual(p.disk_size, 40)
        self.assertEqual(p.cpus, 8)
        self.assertListEqual(p.vlans, [21, 22, 23, 24])
        self.assertEqual(p.mgmt_address, '172.16.1.1')
        self.assertEqual(p.mgmt_net_width, 24)
        self.assertEqual(p.mgmt_gw, '172.16.1.254')
        self.assertEqual(p.mgmt_user, 'admin-cm')
        self.assertEqual(p.mgmt_password, 's3KrI!T')
        self.assertEqual(p.ext_net_name, 'DemoNet123')
        self.assertEqual(p.ext_vlan_name, 'ExtDemoVlan')
        self.assertEqual(p.int_vlan_name, 'IntDemoVlan')
        self.assertEqual(p.ext_vlan_tag, 21)
        self.assertEqual(p.int_vlan_tag, 22)
        self.assertEqual(p.ext_ip_addr, '192.168.1.1/24')
        self.assertEqual(p.int_ip_addr, '192.168.2.1/24')
        self.assertEqual(p.ha_dp_vlan_name, 'dp-demo-ha')
        self.assertEqual(p.ha_cp_vlan_name, 'cp-demo-ha')
        self.assertEqual(p.ha_dp_vlan_tag, 23)
        self.assertEqual(p.ha_cp_vlan_tag, 24)

    def test_ip_validation_ipv6(self):
        args = dict(
            instance=dict(
                internal_ip_address='2001:0db8:85a3:0000:0000:8a2e:0370:7334'
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err1:
            p.int_ip_addr

        self.assertIn(
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334 is not provided in a CIDR format.', err1.exception.args[0]
        )

        args = dict(
            instance=dict(
                internal_ip_address='fe80:2030:31:24'
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err2:
            p.int_ip_addr

        self.assertIn('fe80:2030:31:24 is not a valid IP interface address.', err2.exception.args[0])

    def test_ip_validation_ipv4(self):
        args = dict(
            instance=dict(
                internal_ip_address='192.168.1.1'
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err1:
            p.int_ip_addr

        self.assertIn('192.168.1.1 is not provided in a CIDR format.', err1.exception.args[0])

        args = dict(
            instance=dict(
                internal_ip_address='380.168.2.1'
            )
        )
        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err2:
            p.int_ip_addr

        self.assertIn('380.168.2.1 is not a valid IP interface address.', err2.exception.args[0])

    def test_module_parameters_timeout(self):
        args1 = dict(timeout=9)
        args2 = dict(timeout=3601)
        p1 = ModuleParameters(params=args1)
        p2 = ModuleParameters(params=args2)

        with self.assertRaises(F5ModuleError) as err1:
            p1.timeout()

        self.assertIn(
            "Timeout value must be between 10 and 3600 seconds.",
            err1.exception.args[0]
        )

        with self.assertRaises(F5ModuleError) as err2:
            p2.timeout()

        self.assertIn(
            "Timeout value must be between 10 and 3600 seconds.",
            err2.exception.args[0]
        )


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_deploy_f5os.F5Client')
        self.p2 = patch('time.sleep')
        self.m1 = self.p1.start()
        self.p2.start()
        self.m1.return_value = MagicMock()
        self.p3 = patch(
            'ansible_collections.f5networks.next.plugins.modules.cm_next_deploy_f5os.sanitize_sensitive_data'
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

    def test_deploy_instance(self, *args):
        set_module_args(dict(
            state='deploy',
            provider=dict(
                provider_name='ansible-rseries',
                type='rseries',
                image_name='BIG-IP-Next-20.0.1-2.139.10+0.0.136'
            ),
            instance=dict(
                instance_hostname='demoVM01.lab.local',
                mgmt_address='10.144.140.86/24',
                mgmt_gateway='10.144.140.254',
                mgmt_user='admin-cm',
                mgmt_password='s3KrI!T@31',
                vlans=[27, 28, 29, 30],
                disk_size=20,
                cpus=4,
                external_network_name='DefaultL1Network',
                external_vlan_name='ext-tenant',
                external_vlan_tag=30,
                external_ip_address='192.168.1.1/24',
                internal_vlan_name='int-tenant',
                internal_vlan_tag=29,
                internal_ip_address='192.168.2.1/24',
                ha_dp_vlan_name='dp-tenant',
                ha_dp_vlan_tag=28,
                ha_cp_vlan_name='cp-tenant',
                ha_cp_vlan_tag=27
            )
        ))

        expected = [{'tenant_image_name': 'BIG-IP-Next-20.0.1-2.139.10+0.0.136',
                     'tenant_deployment_file': 'BIG-IP-Next-20.0.1-2.139.10+0.0.136.yaml',
                     'vlan_ids': [27, 28, 29, 30], 'disk_size': 20, 'cpu_cores': 4}]

        expected2 = [{'vlans': [{'selfIps': [], 'name': 'cp-tenant', 'tag': 27},
                                {'selfIps': [], 'name': 'dp-tenant', 'tag': 28},
                                {'selfIps': [{'address': '192.168.1.1/24'}], 'name': 'ext-tenant', 'tag': 30},
                                {'selfIps': [{'address': '192.168.2.1/24'}], 'name': 'int-tenant', 'tag': 29}],
                      'l1Link': {'linkType': 'Interface', 'name': '1.1'}, 'name': 'DefaultL1Network'}
                     ]

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )
        mm = ModuleManager(module=module)

        mm.client.get.side_effect = [
            dict(code=200, contents=load_fixture('cm_next_deploy_f5os_provider.json')),
            dict(code=200, contents=dict(count=0))
        ]
        mm.client.post.return_value = dict(code=202, contents=load_fixture('cm_next_deploy_f5os_task_started.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])

        self.assertTrue(results['changed'])
        self.assertEqual(results['message'], 'BIG-IP Next deployment started.')
        self.assertEqual(results['task_id'], 'ee3e5475-8252-4912-87eb-528d9387154e')
        self.assertEqual(mm.client.post.call_args[0][1]['parameters']['hostname'], 'demoVM01.lab.local')
        self.assertListEqual(mm.client.post.call_args[0][1]['parameters']['rseries_properties'], expected)
        self.assertListEqual(
            mm.client.post.call_args[0][1]['parameters']['l1Networks'],
            expected2
        )

    def test_check_deploy_status_wait_off(self, *args):
        set_module_args(dict(
            state='present',
            task_id='ee3e5475-8252-4912-87eb-528d9387154e',
            wait_for_finish=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = dict(code=200, contents=dict(status='running'))

        results = mm.exec_module()

        self.assertFalse(results['changed'])
        self.assertEqual(results['message'], 'BIG-IP Next deployment task still running.')

    def test_check_deploy_status_task_complete(self, *args):
        set_module_args(dict(
            state='present',
            task_id='ee3e5475-8252-4912-87eb-528d9387154e'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = dict(code=200, contents=load_fixture('cm_next_deploy_f5os_task_done.json'))

        results = mm.exec_module()

        self.assertTrue(results['changed'])
        self.assertEqual(results['message'], 'BIG-IP Next deployment successful.')

    def test_check_deploy_status_task_failed(self, *args):
        set_module_args(dict(
            state='present',
            task_id='4c333b99-625f-4aa3-af83-3d255425e8cc',
            wait_for_finish=False
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = dict(code=200, contents=load_fixture('cm_next_deploy_f5os_task_failed.json'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn('Instance deployment failed with the following reason:', err.exception.args[0])

    def test_wait_for_task_timeout(self, *args):
        set_module_args(dict(
            state='present',
            task_id='98ad7355-210c-4aed-bf02-39dcbf2a6588',
            timeout=300
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            mutually_exclusive=self.spec.mutually_exclusive,
            required_if=self.spec.required_if
        )

        mm = ModuleManager(module=module)

        mm.client.get.return_value = dict(code=200, contents=dict(status='running'))

        with self.assertRaises(F5ModuleError) as err:
            mm.exec_module()

        self.assertIn(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions.",
            err.exception.args[0]
        )

    @patch.object(cm_next_deploy_f5os, 'Connection')
    @patch.object(cm_next_deploy_f5os.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            task_id='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_deploy_f5os.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_deploy_f5os, 'Connection')
    @patch.object(cm_next_deploy_f5os.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            task_id='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_deploy_f5os.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    @patch.object(cm_next_deploy_f5os, 'process_json', new_callable=Mock())
    def test_device_call_functions(self, m1):
        set_module_args(dict(
            state='present',
            task_id='98ad7355-210c-4aed-bf02-39dcbf2a6588',
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
            dict(code=404, contents='not found'),
            dict(code=403, contents='forbidden'),
            dict(code=500, contents='internal server error'),
            dict(code=200, contents={}),
            dict(code=200, contents={'_embedded': {'providers': [1, 2, 3]}}),
            dict(code=403, contents='forbidden'),
            dict(code=200, contents=dict(count=0)),
            dict(code=200, contents=dict(count=2)),
            dict(code=200, contents=dict(count=1)),
            dict(code=500, contents='internal server error'),
        ]

        mm.client.post.return_value = dict(code=403, contents='forbidden')

        with self.assertRaises(F5ModuleError) as err1:
            mm.task_exists()

        self.assertIn('The specified deployment task', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm.task_exists()

        self.assertIn('forbidden', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.provider_exists()

        self.assertIn('internal server error', err3.exception.args[0])

        self.assertFalse(mm.provider_exists())

        with self.assertRaises(F5ModuleError) as err4:
            mm.provider_exists()

        self.assertIn('Query returned more than 1 provider with the name', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.instance_exists()

        self.assertIn('forbidden', err5.exception.args[0])

        self.assertFalse(mm.instance_exists())

        with self.assertRaises(F5ModuleError) as err6:
            mm.instance_exists()

        self.assertIn('Query returned more than 1 instance', err6.exception.args[0])

        self.assertTrue(mm.instance_exists())

        with self.assertRaises(F5ModuleError) as err7:
            m1.return_value = {}
            mm.deploy_on_device()

        self.assertIn('forbidden', err7.exception.args[0])

        with self.assertRaises(F5ModuleError) as err8:
            mm._check_task_on_device('foo')

        self.assertIn('internal server error', err8.exception.args[0])

        mm.provider_exists = Mock(return_value=False)

        with self.assertRaises(F5ModuleError) as err9:
            mm.exists()

        self.assertIn('does not exist', err9.exception.args[0])

        mm.exists = Mock(return_value=True)

        self.assertFalse(mm.deploy())
