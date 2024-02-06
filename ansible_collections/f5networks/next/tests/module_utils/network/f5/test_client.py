# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest.mock import Mock
from unittest import TestCase

from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.next.plugins.module_utils.constants import (
    BASE_HEADERS, ROOT
)
from ansible_collections.f5networks.next.plugins.module_utils.client import F5Client

from ansible_collections.f5networks.next.tests.utils.common import connection_response


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


class TestF5NextClient(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.next.cm"
        self.connection = connection_loader.get("ansible.netcommon.httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.client = F5Client(client=self.connection.httpapi)

    def test_GET_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='GET', headers=expected_header
        )

    def test_GET_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink')
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='GET', headers=BASE_HEADERS
        )

    def test_POST_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=expected_header, method='POST'
        )

    def test_POST_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.post('/testlink', payload)
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='POST'
        )

    def test_PUT_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PUT'
        )

    def test_PUT_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.put('/testlink', payload)
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PUT'
        )

    def test_PATCH_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', payload, headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=expected_header, method='PATCH'
        )

    def test_PATCH_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        payload = {'Test': 'Payload'}

        self.client.patch('/testlink', payload)
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', '{"Test": "Payload"}', headers=BASE_HEADERS, method='PATCH'
        )

    def test_DELETE_header_update_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink', headers={'CUSTOM': 'HEADER'})
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='DELETE', headers=expected_header
        )

    def test_DELETE_header_update_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.delete('/testlink')
        self.connection.send.assert_called_once_with(
            ROOT + '/testlink', None, method='DELETE', headers=BASE_HEADERS
        )

    def test_different_scope_without_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'}, scope='api/different/scope')
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            'api/different/scope/testlink', None, method='GET', headers=expected_header
        )

    def test_different_scope_with_additional_headers(self):
        self.connection.send.return_value = connection_response(
            {'FOO': 'BAR', 'BAZ': 'FOO'}
        )

        self.client.get('/testlink', headers={'CUSTOM': 'HEADER'}, scope='api/different/scope')
        expected_header = {'CUSTOM': 'HEADER', 'Content-Type': 'application/json'}
        self.connection.send.assert_called_once_with(
            'api/different/scope/testlink', None, method='GET', headers=expected_header
        )
