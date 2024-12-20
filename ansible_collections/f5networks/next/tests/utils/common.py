# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json

from unittest.mock import Mock, MagicMock

from ansible.module_utils.six import BytesIO
from ansible_collections.f5networks.next.plugins.module_utils.constants import BASE_HEADERS


def connection_response(response, status=200, headers=None):
    response_mock = Mock()
    response_mock.getcode.return_value = status
    if headers is None:
        headers = BASE_HEADERS
    response_mock.getheaders.return_value = headers.items()
    response_text = json.dumps(response) if isinstance(response, dict) else response
    response_data = BytesIO(response_text.encode() if response_text else ''.encode())
    return response_mock, response_data


def download_response(file, status=200, headers=None):
    response_mock = MagicMock()
    bytes_file = bytes(file, encoding='utf8')
    response_mock_buffer = BytesIO(bytes_file)
    response_mock.status = status
    content_range = '0-{0}/{1}'.format(str(len(bytes_file)), str(len(bytes_file)))
    response_mock.headers = {
        'Content-Type': 'application/octet-stream'
    }
    if headers:
        response_mock.headers.update(headers)
    else:
        response_mock.headers.update({'Content-Range': content_range})
    return response_mock, response_mock_buffer
