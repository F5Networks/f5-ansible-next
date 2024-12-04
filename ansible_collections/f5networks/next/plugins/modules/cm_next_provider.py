#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_next_provider
short_description: Manage providers on Central Manager
description:
  - Manage providers on Central Manager.
version_added: 1.0.0
options:
  name:
    description:
      - Specifies the name of the provider on CM to create or manage.
    type: str
    required: True
  type:
    description:
      - Specifies the type of provider.
    type: str
    required: True
    choices:
      - rseries
      - velos
      - vsphere
  address:
    description:
      - The address of the provider to which Central Manager can connect to.
      - The address may be a hostname or an IP address.
      - The parameter must be specified when creating a new provider.
    type: str
  port:
    description:
      - The port on which Central Manager can connect to provider.
      - The parameter is required when C(type) is C(velos) or C(rseries).
    type: int
  username:
    description:
      - The username that the Central Manager uses when connecting with the specified provider.
      - The parameter must be specified when creating a new provider.
    type: str
  password:
    description:
      - The password that the Central Manager uses when connecting with the specified provider.
      - The parameter must be specified when C(username) is defined.
    type: str
  cert_fingerprint:
    description:
      - The fingerprint of the certificate that the Central Manager uses when connecting with the specified provider.
    type: str
    version_added: "1.1.0"
  force:
    description:
      - When C(true), forces update of the existing provider, this option is required when attempting to change
        existing provider's C(username) and C(password).
      - When C(false), update is not performed when there is no change present.
    type: bool
    default: false
  state:
    description:
      - When C(state) is C(present), ensures the provider is created.
      - When C(state) is C(absent), ensures the provider is removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy (@RavinderReddyF5)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Create a vsphere provider
  cm_next_provider:
    name: "ansible-vsphere"
    type: "vsphere"
    address: "dummy.host.net"
    username: "admin"
    password: "test"

- name: Create an F5OS provider
  cm_next_provider:
    name: "ansible-f5os"
    type: "rseries"
    address: "192.168.1.1"
    port: 8888
    username: "admin"
    password: "test"

- name: Update a username on provider
  cm_next_provider:
    name: "ansible-f5os"
    type: "rseries"
    username: "non-admin"
    password: "test"

- name: Update a password on a provider - force on
  cm_next_provider:
    name: "ansible-f5os"
    type: "rseries"
    password: "changed"
    force: "yes"

- name: Remove a vsphere provider
  cm_next_provider:
    name: "ansible-vsphere"
    type: "vsphere"
    state: "absent"
'''

RETURN = r'''
name:
  description: The name of the provider on CM.
  returned: changed
  type: str
  sample: my_provider
type:
  description: The type of provider.
  returned: changed
  type: str
  sample: rseries
address:
  description: The address of the provider to which Central Manager can connect to.
  returned: changed
  type: str
  sample: 192.168.1.1
port:
  description: The port on which Central Manager can connect to provider.
  returned: changed
  type: int
  sample: 8888
username:
  description: The username that the Central Manager uses when connecting with the specified provider.
  returned: changed
  type: str
  sample: admin
'''
from urllib.parse import quote

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client
from ..module_utils.templates.provider import create

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)
from ..module_utils.logging import sanitize_sensitive_data


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        'name',
        'type',
        'host',
        'username',
        'password',
        'cert_fingerprint',
    ]

    returnables = [
        'name',
        'type',
        'host',
        'username',
        'password',
        'cert_fingerprint',
    ]

    updatables = [
        'host',
        'username',
    ]


class ApiParameters(Parameters):
    @property
    def username(self):
        if self._values['connection'] is None:
            return None
        return self._values['connection']['authentication']['username']

    @property
    def host(self):
        if self._values['connection'] is None:
            return None
        return self._values['connection']['host']


class ModuleParameters(Parameters):
    @property
    def type(self):
        if self._values['type'] is None:
            return None
        return self._values['type'].upper()

    @property
    def host(self):
        if self._values['address'] is None:
            return None
        port = self.port
        if port:
            return f"{self._values['address']}: {port}"
        else:
            return self._values['address']

    @property
    def port(self):
        if self._values['port'] is None:
            return None
        if 0 < self._values['port'] > 65535:
            raise F5ModuleError(
                "Specified port number is out of valid range, correct range is between 0 and 65535."
            )
        return self._values['port']


class Changes(Parameters):
    def to_return(self):  # pragma: no cover
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    returnables = [
        'address',
        'port',
        'username',
        'type',
        'name'
    ]

    @property
    def address(self):
        if self._values['host'] is None:
            return None
        address = self._values['host'].split(':')[0]
        return address

    @property
    def port(self):
        if self._values['host'] is None:
            return None
        port = self._values['host'].split(':')
        if len(port) > 1:
            return int(port[1])

    @property
    def type(self):
        if self._values['type'] is None:
            return None
        return self._values['type'].lower()


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:  # pragma: no cover
            return attr1


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.provider_uuid = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):  # pragma: no cover
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):  # pragma: no cover
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def log_message(self, msg, level='info'):
        self.client.plugin.send_log(msg, level, self.module._name)

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update() and not self.want.force:
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def validate_create_parameters(self):
        if self.want.username is None:
            self.log_message("The 'username' parameter must be provided when creating a new resource.", 'error')
            raise F5ModuleError("The 'username' parameter must be provided when creating a new resource.")
        if self.want.address is None:
            self.log_message("The 'address' parameter must be provided when creating a new resource.", 'error')
            raise F5ModuleError("The 'address' parameter must be provided when creating a new resource.")
        if self.want.port is None and self.want.type != 'VSPHERE':
            self.log_message(f"The 'port' parameter must be provided when provider type is {self.want.type}.", 'error')
            raise F5ModuleError(f"The 'port' parameter must be provided when provider type is {self.want.type}.")

    def populate_update_parameters(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['type'] = self.want.type
        if not params.get('host'):
            params['host'] = self.have.host
        if not params.get('username'):
            params['username'] = self.have.username
        if self.want.password and self.want.force:
            params['password'] = self.want.password
        return params

    def exists(self):
        if self.want.type == 'VELOS' or self.want.type == 'RSERIES':
            query = f"?filter=name+eq+'{self.want.name}'+and+type+eq+'{self.want.type}'"
            uri = f"/device/v1/providers/f5os{query}"
        else:
            uri = f"/device/v1/providers/vsphere?filter=name+eq+'{self.want.name}'"

        uri = quote(uri)
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message("Provider not found")
            return False

        if len(response['contents']['_embedded']['providers']) > 1:
            self.log_message(f"Query returned more than 1 provider with the name: {self.want.name}", 'error')
            raise F5ModuleError(
                f"Query returned more than 1 provider with the name: {self.want.name}"
            )

        self.provider_uuid = response['contents']['_embedded']['providers'][0]['id']
        self.log_message(f"Found provider: {self.provider_uuid}")

        return True

    def create_on_device(self):
        self.validate_create_parameters()
        params = self.changes.api_params()
        self.log_message(
            f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}"
        )

        output = process_json(params, create)

        self.log_message(
            f"Generated JSON: {sanitize_sensitive_data(output, self.client.to_obfuscate())}"
        )

        if self.want.type == 'VELOS' or self.want.type == 'RSERIES':
            uri = "/device/v1/providers/f5os"
        else:
            uri = "/device/v1/providers/vsphere"

        response = self.client.post(uri, output)

        if response['code'] == 500:
            params['cert_fingerprint'] = response['contents'].split()[1][:-1].replace("'", "")
            output = process_json(params, create)
            response = self.client.post(uri, output)
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        self.log_message("Provider creation successful")
        return True

    def update_on_device(self):
        params = self.populate_update_parameters()
        self.log_message(
            f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        output = process_json(params, create)

        self.log_message(
            f"Generated JSON: {sanitize_sensitive_data(output, self.client.to_obfuscate())}")

        if self.want.type == 'VELOS' or self.want.type == 'RSERIES':
            uri = f"/device/v1/providers/f5os/{self.provider_uuid}"
        else:
            uri = f"/device/v1/providers/vsphere/{self.provider_uuid}"

        response = self.client.put(uri, output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        self.log_message("Provider update successful")
        return True

    def remove_from_device(self):
        if self.want.type == 'VELOS' or self.want.type == 'RSERIES':
            uri = f"/device/v1/providers/f5os/{self.provider_uuid}"
        else:
            uri = f"/device/v1/providers/vsphere/{self.provider_uuid}"

        response = self.client.delete(uri)

        if response['code'] in [200, 201, 202, 204]:
            self.log_message("Provider removal successful")
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        if self.want.type == 'VELOS' or self.want.type == 'RSERIES':
            uri = f"/device/v1/providers/f5os/{self.provider_uuid}"
        else:
            uri = f"/device/v1/providers/vsphere/{self.provider_uuid}"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message(f"Configuration read from device: {sanitize_sensitive_data(response['contents'], self.client.to_obfuscate())}")
        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            type=dict(
                required=True,
                choices=['rseries', 'velos', 'vsphere']
            ),
            address=dict(),
            port=dict(type='int'),
            cert_fingerprint=dict(no_log=True),
            username=dict(),
            password=dict(no_log=True),
            force=dict(type='bool', default='no'),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),

        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_by = {
            'username': 'password'
        }


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_by=spec.required_by,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
