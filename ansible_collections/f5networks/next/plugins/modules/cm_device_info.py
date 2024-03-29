#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_device_info
short_description: Collect information from CM devices
description:
  - Collect information from CM devices.
version_added: "1.0.0"
options:
  gather_subset:
    description:
      - When supplied, this argument restricts the information returned to a given subset.
      - You can specify a list of values to include a larger subset.
      - Values can also be used with an initial C(!) to specify that a specific subset
        should not be collected.
    type: list
    elements: str
    required: True
    choices:
      - all
      - files
      - managed-devices
      - users
      - providers
      - "!all"
      - "!files"
      - "!managed-devices"
      - "!users"
      - "!providers"
    aliases: ['include']
author:
  - Ravinder Reddy (@RavinderReddyF5)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Collect users and files information on CM device
  cm_device_info:
    gather_subset:
      - users
      - files

- name: Collect all CM device information
  cm_device_info:
    gather_subset:
      - all

- name: Collect all CM device information except managed-devices
  cm_device_info:
    gather_subset:
      - all
      - "!managed-devices"
'''

RETURN = r'''
files:
  description: Information about files stored on the CM platform.
  returned: When C(files) is specified in C(gather_subset).
  type: complex
  contains:
    file_name:
      description:
        - Name of the file stored on the CM device.
      returned: queried
      type: str
      sample: "foo_file"
    file_size:
      description:
        - File size in bytes.
      returned: queried
      type: int
      sample: 885694
    description:
      description:
        - Description of the file stored on the CM device.
      returned: queried
      type: str
      sample: "this is a new file"
    id:
      description:
        - The system generated UUID of the file.
      returned: queried
      type: str
      sample: "1b0c260c-fc5c-4b82-a781-09eac76cdd09"
    updated:
      description:
        - The timestamp of when the file has been last updated.
        - Formatted in the ISO8601 format.
      returned: queried
      type: str
      sample: "2023-09-05T12:45:04.871517Z"
    hash:
      description:
        - The system generated HASH of the file.
      returned: queried
      type: str
      sample: "080c62dcc1720"
  sample: hash/dictionary of values
managed_devices:
  description: Information about BIG-IP Next instances managed by the CM platform.
  returned: When C(managed-devices) is specified in C(gather_subset).
  type: complex
  contains:
    address:
      description:
        - The IP address of the BIG-IP Next instance.
      returned: queried
      type: str
      sample: "192.168.1.1"
    hostname:
      description:
        - The hostname of the BIG-IP Next instance.
      returned: queried
      type: str
      sample: "foo.bar.net"
    mode:
      description:
        - The operational mode of the BIG-IP Next instance.
      returned: queried
      type: str
      sample: "STANDALONE"
    id:
      description:
        - The system generated ID for the managed BIG-IP Next instance.
      returned: queried
      type: str
      sample: "a17209c8-eb8a"
    version:
      description:
        - The current software version running on the BIG-IP Next instance.
      returned: queried
      type: str
      sample: "20.0.0-2.94.0+0.0.21"
    port:
      description:
        - The port on which BIG-IP Next instance is communicating with CM.
      returned: queried
      type: int
      sample: 5443
    health:
      description:
        - Detailed information on the state of the BIG-IP Next instance.
      returned: queried
      sample: hash/dictionary of values
      type: dict
      contains:
        status:
          description:
            - Current status of the BIG-IP Next instance.
          returned: queried
          type: str
          sample: "UNKNOWN"
        node_count:
          description:
            - The number of nodes that the instance is running on.
          returned: queried
          type: int
          sample: 1
        nodes:
          description:
            - Detailed information about each node in BIG-IP Next instance.
          returned: queried
          type: complex
          contains:
            address:
              description:
                - The IP address of the node in BIG-IP Next instance.
              returned: queried
              type: str
              sample: "192.168.1.1"
            hostname:
              description:
                - The hostname of the node in BIG-IP Next instance.
              returned: queried
              type: str
              sample: "foo.bar.net"
            port:
              description:
                - The port of the node in BIG-IP Next instance.
              returned: queried
              type: int
              sample: 5443
            version:
              description:
                - The version of software running on the node in BIG-IP Next instance.
              returned: queried
              type: str
              sample: "20.0.0-2.94.0+0.0.21"
            state:
              description:
                - The state of the node in BIG-IP Next instance.
              returned: queried
              type: str
              sample: "UNREACHABLE"
    files:
      description:
        - Detailed information on the files uploaded to the BIG-IP Next instance.
      returned: queried
      sample: hash/dictionary of values
      type: dict
      contains:
        file_name:
          description:
            - Name of the file stored on the BIG-IP Next instance.
          returned: queried
          type: str
          sample: "foo_file"
        size:
          description:
            - File size in bytes.
          returned: queried
          type: int
          sample: 885694
        description:
          description:
            - Description of the file stored on the BIG-IP Next instance.
          returned: queried
          type: str
          sample: "this is a new file"
        id:
          description:
            - The system generated UUID of the file.
          returned: queried
          type: str
          sample: "1b0c260c-fc5c-4b82-a781-09eac76cdd09"
        uri:
          description:
            - The system generated URI of the file location.
          returned: queried
          type: str
          sample: "file://opt/f5/mbip/subsystem/csm/shared/persisted/files/f516d6-e0f5243a-ff74-4fe1-8163-7d6e6b4c0cb9"
        hash:
          description:
            - The system generated HASH of the file.
          returned: queried
          type: str
          sample: "080c62dcc1720"
  sample: hash/dictionary of values
users:
  description: Information about users on the CM platform.
  returned: When C(users) is specified in C(gather_subset).
  type: dict
  contains:
    username:
      description:
        - The username of the user.
      returned: queried
      type: str
      sample: "admin-cm"
    email:
      description:
        - The email address configured for the given user.
      returned: queried
      type: str
      sample: "foo@mail.net"
    id:
      description:
        - The system generated UUID of the user.
      returned: queried
      type: str
      sample: "1b0c260c-fc5c-4b82-a781-09eac76cdd09"
    change_password:
      description:
        - Indicates if user is forced to change password upon next login.
      returned: queried
      type: bool
      sample: true
  sample: hash/dictionary of values
'''

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.connection import Connection
from ansible.module_utils.six import (
    iteritems, string_types
)

from ..module_utils.client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.logging import sanitize_sensitive_data


class BaseManager:
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)
        self.kwargs = kwargs

    def log_message(self, msg, level='info'):
        self.client.plugin.send_log(msg, level, self.module._name)


class Parameters(AnsibleF5Parameters):
    @property
    def gather_subset(self):
        if isinstance(self._values['gather_subset'], string_types):
            self._values['gather_subset'] = [self._values['gather_subset']]
        elif not isinstance(self._values['gather_subset'], list):
            raise F5ModuleError(
                "The specified gather_subset must be a list."
            )
        tmp = list(set(self._values['gather_subset']))
        tmp.sort()
        self._values['gather_subset'] = tmp

        return self._values['gather_subset']


class BaseParameters(Parameters):
    api_map = {}
    returnables = []

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result


class FilesParameters(BaseParameters):
    returnables = [
        'file_name',
        'file_size',
        'description',
        'id',
        'updated',
        'hash'
    ]


class FilesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(FilesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(files=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['file_name'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = FilesParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/system/v1/files"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message("No files information obtained from CM")
            return []

        self.log_message(
            f"Files found on CM: "
            f"{sanitize_sensitive_data(response['contents']['_embedded']['files'], self.client.to_obfuscate())}"
        )
        return response['contents']['_embedded']['files']


class ManagedDevicesParameters(BaseParameters):
    returnables = [
        'address',
        'hostname',
        'mode',
        'id',
        'version',
        'port',
        'health',
        'files'
    ]

    @staticmethod
    def _process_nodes(nodes):
        results = list()
        for node in nodes:
            element = dict()
            element['address'] = node['address']
            element['port'] = node['port']
            element['hostname'] = node['hostname']
            element['version'] = node['version']
            element['state'] = node['state']
            results.append(element)
        results = sorted(results, key=lambda k: k['hostname'])
        return results

    @property
    def health(self):
        result = dict()
        result['status'] = self._values['health']['status']
        result['node_count'] = self._values['health']['node_count']
        result['nodes'] = self._process_nodes(self._values['health']['nodes'])
        return result

    @property
    def files(self):
        if self._values['files'] is None:
            return None
        results = list()
        for file in self._values['files']:
            element = dict()
            element['file_name'] = file['fileName']
            element['hash'] = file['hash']
            element['id'] = file['id']
            element['size'] = file['size']
            element['uri'] = file['uri']
            element['description'] = file['description']
            results.append(element)
        results = sorted(results, key=lambda k: k['file_name'])
        return results


class ManagedDevicesFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ManagedDevicesFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(managed_devices=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['hostname'])
        return results

    def read_facts(self):
        results = []
        devices = self.read_collection_from_device()
        for device in devices:
            attrs = device
            attrs['health'] = self.read_device_health_status(device['id'])
            if attrs['health']['status'] == 'HEALTHY':
                attrs['files'] = self.list_device_files(device['id'])
            params = ManagedDevicesParameters(params=attrs)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/device/v1/inventory"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message("No managed devices information obtained from CM")
            return []

        self.log_message(
            f"Retrieved managed devices: "
            f"{sanitize_sensitive_data(response['contents']['_embedded']['devices'], self.client.to_obfuscate())}"
        )
        return response['contents']['_embedded']['devices']

    def read_device_health_status(self, uuid):
        uri = f"/device/v1/inventory/{uuid}/health"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message(f"Got health status for device {uuid}: "
                         f"{sanitize_sensitive_data(response['contents'], self.client.to_obfuscate())}"
                         )
        return response['contents']

    def list_device_files(self, uuid):
        uri = f"/device/v1/proxy/{uuid}?path=files"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message(f"No files found on device {uuid}")
            return []

        self.log_message(
            f"Files found on device {uuid}: "
            f"{sanitize_sensitive_data(response['contents']['_embedded']['files'], self.client.to_obfuscate())}"
        )
        return response['contents']['_embedded']['files']


class UsersParameters(BaseParameters):
    returnables = [
        'change_password',
        'email',
        'id',
        'username'
    ]

    api_map = {
        'force_change_password': 'change_password'
    }


class UsersFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(UsersFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(users=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['username'])
        return results

    def read_facts(self):
        results = []
        collection = self.read_collection_from_device()
        for resource in collection:
            params = UsersParameters(params=resource)
            results.append(params)
        return results

    def read_collection_from_device(self):
        uri = "/system/v1/users"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message("No users found on CM")
            return []

        self.log_message(
            f"Following users found on CM: "
            f"{sanitize_sensitive_data(response['contents']['_embedded']['users'], self.client.to_obfuscate())}"
        )
        return response['contents']['_embedded']['users']


class ProvidersParameters(BaseParameters):
    returnables = [
        'type',
        'id',
        'name',
        'username'
    ]

    @property
    def username(self):
        return self._values['connection']['authentication']['username']


class ProvidersFactManager(BaseManager):
    def __init__(self, *args, **kwargs):
        self.client = kwargs.get('client', None)
        self.module = kwargs.get('module', None)
        super(ProvidersFactManager, self).__init__(**kwargs)

    def exec_module(self):
        facts = self._exec_module()
        result = dict(providers=facts)
        return result

    def _exec_module(self):
        results = []
        facts = self.read_facts()
        for item in facts:
            attrs = item.to_return()
            results.append(attrs)
        results = sorted(results, key=lambda k: k['username'])
        return results

    def read_facts(self):
        results = []
        vsphere = self.read_collection_from_device()
        f5os = self.read_collection_from_device(True)
        if vsphere:
            for resource in vsphere:
                params = ProvidersParameters(params=resource)
                results.append(params)
        if f5os:
            for resource in f5os:
                params = ProvidersParameters(params=resource)
                results.append(params)
        return results

    def read_collection_from_device(self, f5os=False):
        if f5os:
            uri = '/device/v1/providers/f5os'
        else:
            uri = '/device/v1/providers/vsphere'
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message('No providers found on CM')
            return []

        self.log_message(
            f"Providers found on CM: "
            f"{sanitize_sensitive_data(response['contents']['_embedded']['providers'], self.client.to_obfuscate())}"
        )
        return response['contents']['_embedded']['providers']


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.kwargs = kwargs
        self.want = Parameters(params=self.module.params)
        self.managers = {
            'files': FilesFactManager,
            'managed-devices': ManagedDevicesFactManager,
            'users': UsersFactManager,
            'providers': ProvidersFactManager
        }

    def exec_module(self):
        self.handle_all_keyword()
        self.filter_excluded_meta_facts()
        result = self.filter_excluded_facts()

        managers = []
        for name in result:
            manager = self.get_manager(name)
            if manager:
                managers.append(manager)

        if not managers:
            result = dict(
                queried=False
            )
            return result

        result = self.execute_managers(managers)
        if result:
            result['queried'] = True
        else:
            result['queried'] = False
        return result

    def filter_excluded_meta_facts(self):
        gather_subset = set(self.want.gather_subset)
        gather_subset -= {'!all'}

        if '!all' in self.want.gather_subset:
            gather_subset.clear()

        self.want.update({'gather_subset': list(gather_subset)})

    def filter_excluded_facts(self):
        # Remove the excluded entries from the list of possible facts
        exclude = [x[1:] for x in self.want.gather_subset if x[0] == '!']
        include = [x for x in self.want.gather_subset if x[0] != '!']
        result = [x for x in include if x not in exclude]
        return result

    def handle_all_keyword(self):
        if 'all' not in self.want.gather_subset:
            return
        managers = list(self.managers.keys()) + self.want.gather_subset
        managers.remove('all')
        self.want.update({'gather_subset': managers})

    def execute_managers(self, managers):
        results = dict()
        for manager in managers:
            result = manager.exec_module()
            results.update(result)
        return results

    def get_manager(self, which):
        result = {}
        manager = self.managers.get(which, None)
        if not manager:
            return result
        kwargs = dict()
        kwargs.update(self.kwargs)

        kwargs['client'] = F5Client(module=self.module, client=self.connection)
        result = manager(**kwargs)
        return result


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            gather_subset=dict(
                type='list',
                elements='str',
                required=True,
                aliases=['include'],
                choices=[
                    # Meta choices
                    'all',

                    # Non-meta choices
                    'files',
                    'managed-devices',
                    'users',
                    'providers',

                    # Negations of meta choices
                    '!all',

                    # Negations of non-meta-choices
                    '!files',
                    '!managed-devices',
                    '!users',
                    '!providers',
                ]
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()

        ansible_facts = dict()

        for key, value in iteritems(results):
            key = 'ansible_net_%s' % key
            ansible_facts[key] = value

        module.exit_json(ansible_facts=ansible_facts, **results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
