# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
name: cm
short_description: HttpApi Plugin for CM NEXT devices
description:
  - This HttpApi plugin provides methods to connect to CM NEXT devices over a HTTP(S)-based API.
version_added: "1.0.0"
options:
  debug_mode:
    type: boolean
    description:
      - Whether to use enable debug_mode for more verbose output in F5 modules.
      - The output is saved in the system's temporary directory.
      - The output filename follows the pattern of C(running_module_name-current_datetime-debug.log)
    default: false
    vars:
    - name: f5_debug
  debug_level:
    type: str
    description:
      - What level of debugging should should be set.
    default: info
    choices:
      - debug
      - info
      - warning
      - error
      - critical
    vars:
    - name: f5_debug_level
  obfuscate_list:
    type: list
    elements: str
    description:
      - List of sensitive entries to obfuscate from debug logs.
      - By default username and password used to log in to the CM device, as well as any parameter that is marked
        as C(no_log) in the calling module are obfuscated.
      - If there is a need to obfuscate additional sensitive information from response or request logs, their values
        should be put on this list.
    vars:
    - name: f5_secrets
author:
  - Wojciech Wypior (@wojtek0806)
'''
import json

from ansible.module_utils.basic import to_text
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import prepare_multipart
from ansible.errors import AnsibleConnectionFailure

from ansible_collections.f5networks.next.plugins.module_utils.constants import (
    LOGIN, BASE_HEADERS, LOG_LEVELS
)
from ansible_collections.f5networks.next.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.next.plugins.module_utils.logging import return_logger, sanitize_sensitive_data


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        self.access_token = None
        self.refresh_token = None
        self.has_logging = False
        self.log = None
        self.secrets = []

    def login(self, username, password):
        self.send_log("Not authenticated, will attempt to login")
        if username and password:
            payload = {
                'username': username,
                'password': password
            }
            if self.get_option('obfuscate_list'):
                self.update_secrets(self.get_option('obfuscate_list'))
            self.update_secrets([username, password])
            response = self.send_request(path=LOGIN, method='POST', payload=payload, headers=BASE_HEADERS)
        else:
            self.send_log('Username and password are required for login.', 'error')
            raise AnsibleConnectionFailure('Username and password are required for login.')

        if response['code'] == 200:
            self.access_token = response['contents'].get('access_token')
            self.refresh_token = response['contents'].get('refresh_token')
            if self.access_token:
                self.connection._auth = {'Authorization': 'Bearer' + ' ' + self.access_token}
                self.send_log("Login successful")
            else:
                self.send_log('Server returned invalid response during connection authentication.', 'error')
                raise AnsibleConnectionFailure('Server returned invalid response during connection authentication.')
        else:
            self.send_log(f"Authentication process failed, server returned: {response['contents']}", 'error')
            raise AnsibleConnectionFailure(f"Authentication process failed, server returned: {response['contents']}")

    def token_refresh(self):
        payload = {
            'refresh_token': {
                self.refresh_token
            }
        }
        response = self.send_request(
            path="/api/token-refresh", method='POST', payload=payload, headers=BASE_HEADERS
        )

        if response['code'] == 200:
            self.access_token = response['contents'].get('access_token')
            if self.access_token:
                self.connection._auth = {'Authorization': 'Bearer' + ' ' + self.access_token}
                self.send_log("Token refresh successful")
            else:
                self.send_log('Server returned invalid response during token refresh.', 'error')
                raise AnsibleConnectionFailure('Server returned invalid response during token refresh.')
        else:
            self.send_log(f"Token refresh process failed, server returned: {response['contents']}", 'error')
            raise AnsibleConnectionFailure(f"Token refresh process failed, server returned: {response['contents']}")

    def logout(self):
        response = self.send_request(
            path="/api/logout", method='POST', payload={}, headers=BASE_HEADERS
        )
        if response['code'] == 204:
            self.send_log("Logout successful")
            return True

    def handle_httperror(self, exc):
        if exc.code == 401:
            if self.connection._auth:
                # only attempt to refresh token if we were connected before not when we get 401 on first attempt
                self.connection._auth = None
                self.send_log("Auth token expired")
                self.token_refresh()
                return True
        return False

    def send_request(self, **kwargs):
        url = kwargs.pop('path', '/')
        body = kwargs.pop('payload', None)
        method = kwargs.pop('method', None)
        # allow for empty json to be passed as payload, useful for some endpoints
        data = json.dumps(body) if body or body == {} else None
        try:
            self._log_api_call(method, url, body)
            response, response_data = self.connection.send(url, data, method=method, **kwargs)
            response_value = self._get_response_value(response_data)
            self._log_api_response(response, response_value)
            return dict(
                code=response.getcode(),
                contents=self._response_to_json(response_value),
                headers=dict(response.getheaders())
            )
        except HTTPError as e:
            self._log_api_response(e, is_error=True)
            return dict(code=e.code, contents=json.loads(e.read()))

    def _log_api_call(self, method, url, data=None):
        if data:
            self.send_log(
                f"NEXT API Call: {method} to {url} with data {sanitize_sensitive_data(data, self.secrets)}",
                'debug'
            )
        else:
            self.send_log(f"NEXT API Call: {method} to {url}", 'debug')

    def _log_api_response(self, response, response_value=None, is_error=False):
        if is_error:
            self.send_log(f"NEXT API HTTP Error Code: {response.code}", 'debug')
            self.send_log(f"NEXT API HTTP Error Headers: {response.headers}", 'debug')
            self.send_log(
                f"NEXT API HTTP Error Body: {sanitize_sensitive_data(json.loads(response.read()), self.secrets)}",
                'debug'
            )
            # need to rewind the buffer
            response.seek(0)
        elif response and response_value:
            self.send_log(f"NEXT API Response Code: {response.getcode()}", 'debug')
            self.send_log(f"NEXT API Response Headers: {dict(response.getheaders())}", 'debug')
            self.send_log(f"NEXT API Response Body: "
                          f"{sanitize_sensitive_data(self._response_to_json(response_value), self.secrets)}",
                          'debug')

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        except json.JSONDecodeError:
            self.send_log(f"Invalid JSON response: {response_text}", 'error')
            raise F5ModuleError(f"Invalid JSON response: {response_text}")

    def send_multipart(self, url, form):
        res = prepare_multipart(form)
        h = {"Content-Type": res[0], "Content-Length": len(res[1])}
        try:
            response, response_data = self.connection.send(url, res[1], method='POST', headers=h)
            response_value = self._get_response_value(response_data)
            self._log_api_response(response, response_value)
            return dict(
                code=response.getcode(),
                contents=self._response_to_json(response_value),
                headers=dict(response.getheaders())
            )
        except HTTPError as e:
            self._log_api_response(e, is_error=True)
            return dict(code=e.code, contents=json.loads(e.read()))

    def init_logger(self, mod_name):
        if self.get_option('debug_mode'):
            self.log = return_logger(mod_name)
            self.log.setLevel(LOG_LEVELS[self.get_option('debug_level')])
            self.has_logging = True

    def send_log(self, msg, level='info', mod='cm'):
        if not self.has_logging:
            return
        logger = getattr(self.log, level, None)
        if logger is not None and callable(logger):
            logger(msg, extra=dict(mod=mod))

    def update_secrets(self, item):
        if isinstance(item, list):
            self.secrets.extend(item)
        elif isinstance(item, str):
            self.secrets.append(item)
        else:
            raise ValueError('only strings and lists are supported')

    def return_no_log(self):
        return self.secrets[:-1]
