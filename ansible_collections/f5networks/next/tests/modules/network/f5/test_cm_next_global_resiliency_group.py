# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_next_global_resiliency_group
from ansible_collections.f5networks.next.plugins.modules.cm_next_global_resiliency_group import (
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
            name='testGRG',
            dns_listener_name='testDNSListener',
            dns_listener_port=8888,
            protocols=['udp', 'tcp'],
            instances=[
                dict(
                    address='10.218.133.144',
                    hostname='testHost1',
                    dns_listener_address="10.216.122.145",
                    group_sync_address="10.216.122.145/24"
                )
            ]
        )

        p = ModuleParameters(params=args)
        self.assertEqual(p.dns_listener_name, 'testDNSListener')
        self.assertEqual(p.dns_listener_port, 8888)
        self.assertEqual(p.protocols, ['udp', 'tcp'])
        self.assertEqual(p.instances, args['instances'])
        self.assertEqual(p.name, 'testGRG')

    def test_module_parameters_timeout(self):
        args = dict(timeout=9)

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.timeout

        self.assertIn('Timeout value must be between 10 and 1800 seconds.', err.exception.args[0])

        args = dict(timeout=1801)

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.timeout

        self.assertIn('Timeout value must be between 10 and 1800 seconds.', err.exception.args[0])


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_global_resiliency_group.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_next_global_resiliency_group.time')
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

    def test_create(self, *args):
        set_module_args(dict(
            name='testGRG',
            dns_listener_name='testDNSListener',
            dns_listener_port=8888,
            protocols=['udp', 'tcp'],
            instances=[
                dict(
                    address='10.218.133.144',
                    hostname='testHost1',
                    dns_listener_address="10.216.122.145",
                    group_sync_address="10.216.122.145/24"
                )
            ],
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        resp_cout_0 = {'code': 200, 'contents': {'count': 0}}
        resp_deploying = {'code': 200, 'contents': {'status': 'DEPLOYING'}}
        resp_deployed = {'code': 200, 'contents': {'status': 'DEPLOYED'}}
        mm.client.get = Mock(side_effect=[resp_cout_0, resp_deploying, resp_deployed])

        posr_resp = {'code': 202, 'contents': {'path': '/v1/gslb/gr-groups/962d1853-e273-4383-a0c9-cd30e9db5138'}}
        mm.client.post = Mock(return_value=posr_resp)

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 3)

    def test_update(self, *args):
        existing_grgs = load_fixture('cm_global_resiliency_groups.json')
        grg_to_update = load_fixture('cm_global_resiliency_group_update.json')

        set_module_args(dict(
            name='testGRG',
            dns_listener_name='testDNSListener',
            dns_listener_port=8888,
            protocols=['udp', 'tcp'],
            instances=[
                dict(
                    address='10.218.134.143',
                    hostname='testHost1',
                    dns_listener_address="10.216.112.145",
                    group_sync_address="10.216.112.145/24"
                )
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        deploying_grg = {'code': 200, 'contents': {'status': 'DEPLOYING'}}
        deployed = {'code': 200, 'contents': {'status': 'DEPLOYED'}}

        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[existing_grgs, grg_to_update, deploying_grg, deployed])
        mm.client.put = Mock(return_value={'code': 202})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.put.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 4)

    def test_update_no_change(self, *args):
        update_grg = load_fixture('cm_global_resiliency_group_update.json')

        set_module_args(dict(
            name='testGRG',
            dns_listener_name='testDNSListener',
            dns_listener_port=8888,
            protocols=['tcp', 'udp'],
            instances=[
                dict(
                    address='10.21.138.232',
                    hostname='big-ip-next',
                    dns_listener_address="10.4.1.56",
                    group_sync_address="10.4.1.56/24"
                )
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.client.get = Mock(return_value=update_grg)

        result = mm.exec_module()

        self.assertFalse(result['changed'])
        self.assertEqual(mm.client.get.call_count, 1)

    def test_delete(self, *args):
        existing_grgs = load_fixture('cm_global_resiliency_groups.json')

        set_module_args(dict(
            name='testGRG',
            state='absent'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        delete_resp = {'code': 202, 'contents': {'message': 'Deleting the Global Resiliency Group'}}
        no_grgs = {'code': 200, 'contents': {'count': 0}}
        mm = ModuleManager(module=module)
        mm.client.get = Mock(side_effect=[existing_grgs, no_grgs])
        mm.client.delete = Mock(return_value=delete_resp)

        result = mm.exec_module()

        self.assertTrue(result)
        self.assertEqual(mm.client.delete.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    @patch.object(cm_next_global_resiliency_group, 'Connection')
    @patch.object(cm_next_global_resiliency_group.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_next_global_resiliency_group.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_next_global_resiliency_group, 'Connection')
    @patch.object(cm_next_global_resiliency_group.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_next_global_resiliency_group.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name='testGRG',
            dns_listener_name='testDNSListener',
            dns_listener_port=8888,
            protocols=['tcp', 'udp'],
            instances=[
                dict(
                    address='10.21.138.232',
                    hostname='big-ip-next',
                    dns_listener_address="10.4.1.56",
                    group_sync_address="10.4.1.56/24"
                )
            ]
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=503, contents='access denied')])

        mm.client.post = Mock(return_value=dict(code=503, contents='server error'))

        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        res3 = mm.absent()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err2:
            mm.remove_from_device = Mock(return_value=True)
            mm.remove()
        self.assertIn('Failed to delete the resource.', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.read_current_from_device()
        self.assertIn('access denied', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.create_on_device()
        self.assertIn('server error', err4.exception.args[0])
