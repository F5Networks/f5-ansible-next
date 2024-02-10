# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_ssl_certificate_create
from ansible_collections.f5networks.next.plugins.modules.cm_ssl_certificate_create import (
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
            locality='Tel',
            country='IN',
            organization='Fx',
            division='QA',
            email='r@fx.com',
            key_type='ECDSA',
            province='Hyd',
            key_security_type='Password',
            key_passphrase='test123',
        )

        p = ModuleParameters(params=args)

        self.assertListEqual(p.locality, ['Tel'])
        self.assertListEqual(p.country, ['IN'])
        self.assertListEqual(p.organization, ['Fx'])
        self.assertListEqual(p.division, ['QA'])
        self.assertListEqual(p.province, ['Hyd'])
        self.assertEqual(p.email, ['r@fx.com'])
        self.assertEqual(p.key_type, 'ECDSA')
        self.assertEqual(p.key_passphrase, 'test123')

    def test_module_parameters_password_exception(self):
        args = dict(
            key_type='ECDSA',
            key_curve_name='prime256v1',
        )

        p = ModuleParameters(params=args)

        with self.assertRaises(F5ModuleError) as err:
            p.key_passphrase

        self.assertIn(
            "key_passphrase is required when key_security_type is set to 'Password'",
            err.exception.args[0]
        )

    def test_api_parameters(self):
        args = dict(
            state='Hyd',
            key=dict(passphrase='key_password_hsm_id')
        )

        p = ApiParameters(params=args)

        self.assertEqual(p.province, 'Hyd')
        self.assertEqual(p.key_security_type, 'Password')


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_ssl_certificate_create.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.p2 = patch('ansible_collections.f5networks.next.plugins.modules.cm_ssl_certificate_create.sanitize_sensitive_data')
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
            name='testcert',
            issuer='Self',
            common_name='test.example.com',
            duration_in_days=365,
            key_type='RSA',
            key_size=2048,
            key_security_type='Normal',
            province='Hyd',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.client.get = Mock(return_value={'code': 200, 'contents': {'count': 0, 'total': 0}})
        mm.client.post = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.get.call_count, 1)
        self.assertEqual(mm.client.post.call_count, 1)

    def test_update(self, *args):
        set_module_args(dict(
            name='testcert',
            common_name='test.example.com',
            duration_in_days=365,
            key_security_type='Password',
            key_passphrase='test123',
            update_passphrase=True,
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        get_resp = load_fixture('cm_get_certificate.json')
        existing_cert = get_resp['_embedded']['certificates'][0]

        mm = ModuleManager(module=module)
        get_side_effects = [
            {'code': 200, 'contents': get_resp},
            {'code': 200, 'contents': existing_cert},
        ]
        mm.client.get = Mock(side_effect=get_side_effects)
        mm.client.post = Mock(return_value={'code': 200})

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.get.call_count, 2)
        self.assertEqual(mm.client.post.call_count, 1)

    def test_update_no_change(self, *args):
        set_module_args(dict(
            name='testcert',
            common_name='test.example.com',
            duration_in_days=365,
            locality='Tel',
            key_security_type='Password',
            key_passphrase='test123',
            state='present',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        get_resp = load_fixture('cm_get_certificate.json')
        existing_cert = get_resp['_embedded']['certificates'][0]

        mm = ModuleManager(module=module)
        get_side_effects = [
            {'code': 200, 'contents': get_resp},
            {'code': 200, 'contents': existing_cert},
        ]
        mm.client.get = Mock(side_effect=get_side_effects)
        # mm.client.post = Mock(return_value={'code': 200})

        result = mm.exec_module()
        self.assertFalse(result['changed'])
        self.assertEqual(mm.client.get.call_count, 2)
        self.assertEqual(mm.client.post.call_count, 0)

    def test_delete(self, *args):
        set_module_args(dict(
            name='testcert',
            state='absent',
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(side_effect=[True, False])
        mm.client.delete = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.delete.call_count, 1)

    @patch.object(cm_ssl_certificate_create, 'Connection')
    @patch.object(cm_ssl_certificate_create.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_ssl_certificate_create.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_ssl_certificate_create, 'Connection')
    @patch.object(cm_ssl_certificate_create.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            state='absent',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_ssl_certificate_create.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            key_type='ECDSA',
            key_security_type='Password',
            duration_in_days=30,
            common_name='foo.org',
            key_passphrase='test123',
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=404),
                                          dict(code=400, contents='server error'),
                                          dict(code=400, contents='server error')])
        mm.client.post = Mock(return_value=dict(code=400, contents='server error'))
        mm.client.delete = Mock(return_value=dict(code=400, contents='server error'))

        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
            mm._set_changed_options()
            mm.create_on_device()
        self.assertIn('server error', err2.exception.args[0])

        with self.assertRaises(F5ModuleError) as err3:
            mm.update_on_device()
        self.assertIn('server error', err3.exception.args[0])

        with self.assertRaises(F5ModuleError) as err4:
            mm.remove_from_device()
        self.assertIn('server error', err4.exception.args[0])

        with self.assertRaises(F5ModuleError) as err5:
            mm.read_current_from_device()
        self.assertIn('server error', err5.exception.args[0])

        mm.exists = Mock(side_effect=[False, True])
        mm.read_current_from_device = Mock()
        mm.should_update = Mock(return_value=False)
        mm.remove_from_device = Mock()

        res2 = mm.absent()
        self.assertFalse(res2)

        res3 = mm.update()
        self.assertFalse(res3)

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove()
        self.assertIn('Failed to delete the resource.', err6.exception.args[0])
