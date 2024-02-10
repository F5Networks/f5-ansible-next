#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_next_files
short_description: Manage NEXT instance files through CM
description:
  - Manage NEXT files through CM.
version_added: "1.0.0"
options:
  device_hostname:
    description:
      - The hostname of the Next instance to manage files on.
      - Parameter mutually exclusive with C(device_ip).
    type: str
  device_ip:
    description:
      - The ip address of the Next instance to manage files on.
      - Parameter mutually exclusive with C(device_hostname).
    type: str
  filename:
    description:
      - The path and filename of the file to be uploaded to Next instance.
    type: path
    required: True
  name:
    description:
      - The name of the file as it should appear on the Next instance.
      - If not provided the parameter is inferred from C(filename).
    type: str
  description:
    description:
      - The description of the uploaded file as it should appear on the Next instance.
    type: str
  timeout:
    description:
      - The amount of time in seconds to wait for the file to appear on NEXT instance.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  force:
    description:
      - When C(true), uploads the file every time and replaces the file on the
        Next instance.
      - When C(false), the file is only uploaded if it does not already
        exist.
    type: bool
    default: false
  state:
    description:
      - When C(present), ensures the file is uploaded.
      - When C(absent), ensures the file is removed.
    type: str
    choices:
      - absent
      - present
    default: present
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Upgrade Next instance
  cm_next_files:
    device_ip: "127.1.1.1"
    filename: "/path/to/file/file.json"
    description: "some file"
    timeout: 600

- name: Upload a file - force on
  cm_next_files:
    device_ip: "127.1.1.1"
    filename: "/path/to/file/file.json"
    description: "some file"
    force: "yes"

- name: Remove a file
  cm_next_files:
    device_ip: "127.1.1.1"
    filename: "/path/to/file/file.json"
    state: absent
'''

RETURN = r'''
device_hostname:
  description: The hostname of the Next instance to manage files on.
  returned: changed
  type: str
  sample: "foo.bar.net"
device_ip:
  description: The ip address of the Next instance to manage files on.
  returned: changed
  type: str
  sample: "192.168.1.1"
filename:
  description: The path and filename of the file to be uploaded to Next instance.
  returned: changed
  type: str
  sample: "/path/to/file.tar"
name:
  description: The name of the file as it should appear on the Next instance.
  returned: changed
  type: str
  sample: "my_file.tar"
description:
  description: The description of the uploaded file as it should appear on the Next instance.
  returned: changed
  type: str
  sample: "this is my file"
'''
import os
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)
from ..module_utils.client import F5Client


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'description',
        'name',
        'filename',
        'device_hostname',
        'device_ip'
    ]

    updatables = []


class ModuleParameters(Parameters):
    @property
    def name(self):
        if self._values['name'] is None:
            return os.path.basename(self._values['filename'])
        return self._values['name']

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 1800:
            raise F5ModuleError(
                "Timeout value must be between 10 and 1800 seconds."
            )
        if timeout > 99:
            divisor = 100
        interval = timeout / divisor
        return interval, divisor


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:  # pragma: no cover
            raise
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.device_uuid = None
        self.file_uuid = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

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

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True

        interval, period = self.want.timeout
        self.create_on_device()
        return self.wait_for_file(interval, period)

    def update(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        if self.want.force:
            # The process of updating is a forced re-creation.
            self.remove_from_device()
            return self.create()
        return False

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.file_exists():
            raise F5ModuleError("File not deleted from target NEXT instance.")
        return True

    def exists(self):
        self.device_exists()
        return self.file_exists()

    def file_exists(self):
        uri = f"/device/v1/proxy/{self.device_uuid}?path=/files"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if any([response['contents'].get('count', 0) == 0, not response['contents'].get('_embedded')]):
            self.log_message("No file found")
            return False

        files = response['contents']['_embedded'].get('files', [])
        for file in files:
            if os.path.basename(self.want.filename) == file['fileName'] and self.want.name == file['name']:
                self.file_uuid = file['id']
                self.log_message(f"File found: {self.file_uuid}")
                return True
        self.log_message("No file found")
        return False

    def device_exists(self):
        if self.want.device_ip:
            uri = f"/device/v1/inventory?filter=address+eq+'{self.want.device_ip}'"
        else:
            uri = f"/device/v1/inventory?filter=hostname+eq+'{self.want.device_hostname}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['count'] == 0:
            self.log_message(
                f"Specified device: {self.want.device_ip if self.want.device_ip else self.want.device_hostname}, "
                f"not found.", 'error'
            )
            raise F5ModuleError(
                f"Specified device: {self.want.device_ip if self.want.device_ip else self.want.device_hostname}"
                f", not found.")

        if response['contents']['count'] == 1:
            self.device_uuid = response['contents']['_embedded']['devices'][0]['id']
            self.log_message(f"Device UUID: {self.device_uuid}")
            return True
        else:
            self.log_message(
                f"Query returned more than 1 device with the specified property: "
                f"{self.want.device_ip if self.want.device_ip else self.want.device_hostname}", 'error'
            )
            raise F5ModuleError(
                f"Query returned more than 1 device with the specified property: "
                f"{self.want.device_ip if self.want.device_ip else self.want.device_hostname} "
            )

    def create_on_device(self):
        form = {
            'fileName': {'filename': self.want.filename,
                         "mime_type": "application/octet-stream"},
            'description': self.want.description,
            'name': self.want.name
        }
        self.log_message(f"Creating file {self.want.filename}")
        self.log_message(f"Form data: {form}")

        uri = f'/api/device/v1/proxy-file-upload/{self.device_uuid}'
        response = self.client.plugin.send_multipart(uri, form)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        self.log_message("File created successfully")
        return True

    def remove_from_device(self):
        uri = f"/device/v1/proxy/{self.device_uuid}?path=/files/{self.file_uuid}"
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("File deleted successfully")
        return True

    def wait_for_file(self, interval, period):
        for x in range(0, period):
            self.log_message(f"Waiting for API to register file, count: {x}", 'debug')
            if self.file_exists():
                return True
            time.sleep(interval)
            self.log_message(f"Pausing for {interval}", 'debug')
        self.log_message("Module timed out, waiting for file", 'error')
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            device_hostname=dict(),
            device_ip=dict(),
            name=dict(),
            description=dict(),
            filename=dict(
                required=True,
                type='path'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            force=dict(type='bool', default='no'),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['device_hostname', 'device_ip']
        ]
        self.required_one_of = [
            ['device_hostname', 'device_ip']
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
        required_one_of=spec.required_one_of
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
