# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.f5networks.next.plugins.modules import cm_ssl_certificate_import
from ansible_collections.f5networks.next.plugins.modules.cm_ssl_certificate_import import (
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
            name='tescert',
            cert_content='foobar',
            key_content='barfoo',
        )

        p1 = ModuleParameters(params=args)
        self.assertEqual(p1.name, 'tescert')
        self.assertEqual(p1.cert_content, 'foobar')

        p2 = ModuleParameters(params=dict())
        self.assertIsNone(p2.cert_checksum)
        self.assertIsNone(p2.key_checksum)

    def test_api_parameters(self):
        api_param = load_fixture('cm_get_certificate.json')
        args = api_param['_embedded']['certificates'][0]

        p1 = ApiParameters(params=args)
        p2 = ApiParameters(params=dict())

        self.assertEqual(p1.name, 'testcert')
        self.assertEqual(p1.id, '859d0bf0-0d6e-40dd-8504-809a4bb3b8ce')
        self.assertEqual(p1.cert_checksum, '6f3e6a4a4d5fe148c173408be61199cbdb74b64ad53198ec463ab28c5')

        self.assertIsNone(p2.cert_checksum)
        self.assertIsNone(p2.key_checksum)


class TestManager(unittest.TestCase):
    def setUp(self):
        self.spec = ArgumentSpec()
        self.p1 = patch('ansible_collections.f5networks.next.plugins.modules.cm_ssl_certificate_import.F5Client')
        self.m1 = self.p1.start()
        self.m1.return_value = MagicMock()
        self.mock_module_helper = patch.multiple(AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)
        self.mock_module_helper.start()

    def tearDown(self):
        self.p1.stop()
        self.mock_module_helper.stop()

    def test_create_cert(self, *args):
        set_module_args(dict(
            name='testcert',
            cert='/path/to/cert',
            key='/path/to/key',
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
        mm.want._return_file_content = Mock(return_value='foobar')

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_update_cert(self, *args):
        set_module_args(dict(
            name='testcert',
            cert='/path/to/cert',
            key='/path/to/key',
            update_cert=True,
            update_key=True,
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
        mm.want._return_file_content = Mock(return_value='foobar')
        get_side_effect = [
            {'code': 200, 'contents': get_resp},
            {'code': 200, 'contents': existing_cert},
        ]
        mm.client.get = Mock(side_effect=get_side_effect)
        mm.client.post = Mock(return_value={'code': 200})

        result = mm.exec_module()

        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 2)

    def test_update_cert_no_change(self, *args):
        set_module_args(dict(
            name='testcert',
            cert='/path/to/cert',
            key='/path/to/key',
            update_cert=False,
            update_key=False,
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode,
            required_if=self.spec.required_if,
            mutually_exclusive=self.spec.mutually_exclusive,
        )

        mm = ModuleManager(module=module)
        mm.exists = Mock(return_value=True)
        mm.read_current_from_device = Mock(return_value=ApiParameters(params=dict()))
        result = mm.exec_module()

        self.assertFalse(result['changed'])

    def test_create_pkcs12_cert(self, *args):
        set_module_args(dict(
            name='testcert',
            cert='/path/to/pkcs12cert',
            pkcs12_passphrase='passWord',
            type='PKCS12',
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
        mm.want._read_pkcs_file = Mock(return_value='foobar')

        result = mm.exec_module()
        self.assertTrue(result['changed'])
        self.assertEqual(mm.client.post.call_count, 1)
        self.assertEqual(mm.client.get.call_count, 1)

    def test_delete_cert(self, *args):
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

    @patch.object(cm_ssl_certificate_import, 'Connection')
    @patch.object(cm_ssl_certificate_import.ModuleManager, 'exec_module', Mock(return_value={'changed': False}))
    def test_main_function_success(self, *args):
        set_module_args(dict(
            name='foobar',
            state='present',
        ))

        with self.assertRaises(AnsibleExitJson) as result:
            cm_ssl_certificate_import.main()

        self.assertFalse(result.exception.args[0]['changed'])

    @patch.object(cm_ssl_certificate_import, 'Connection')
    @patch.object(cm_ssl_certificate_import.ModuleManager, 'exec_module',
                  Mock(side_effect=F5ModuleError('This module has failed.'))
                  )
    def test_main_function_failed(self, *args):
        set_module_args(dict(
            name='foobar',
            cert='/path/to/cert',
            state='present',
            type='PEM',
        ))

        with self.assertRaises(AnsibleFailJson) as result:
            cm_ssl_certificate_import.main()

        self.assertTrue(result.exception.args[0]['failed'])
        self.assertIn('This module has failed.', result.exception.args[0]['msg'])

    def test_device_call_functions(self):
        set_module_args(dict(
            name="foobar",
            state='present'
        ))

        module = AnsibleModule(
            argument_spec=self.spec.argument_spec,
            supports_check_mode=self.spec.supports_check_mode
        )

        mm = ModuleManager(module=module)

        mm.client.get = Mock(side_effect=[dict(code=404), dict(code=400, contents='server error'),
                                          dict(code=503, contents='server error')])

        mm.client.post = Mock(return_value=dict(code=400, contents='server error'))
        mm.client.delete = Mock(return_value=dict(code=400, contents='server error'))

        res1 = mm.exists()
        self.assertFalse(res1)

        with self.assertRaises(F5ModuleError) as err1:
            mm.exists()
        self.assertIn('server error', err1.exception.args[0])

        with self.assertRaises(F5ModuleError) as err2:
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

        mm.exists = Mock(side_effect=[False, True, True])
        res2 = mm.absent()
        self.assertFalse(res2)

        mm.remove_from_device = Mock()

        with self.assertRaises(F5ModuleError) as err6:
            mm.remove()

        self.assertIn('Failed to delete the resource.', err6.exception.args[0])
