#!/usr/bin/python
# -*- coding: utf-8 -*-
# !/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_files
short_description: Manage files uploads/deletes on BIG-IP Next CM
description:
  - Manage files uploads/deletes on BIG-IP Next CM
version_added: "1.0.0"
options:
  filename:
    description:
      - The path and filename of the file to be uploaded.
    type: path
    required: True
  name:
    description:
      - The name of the file as it should appear on the CM.
      - If not provided the parameter is inferred from C(filename).
    type: str
  description:
    description:
      - The description of the uploaded file as it should appear on the CM.
    type: str
  timeout:
    description:
      - The amount of time in seconds to wait for the file to appear on CM.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  force:
    description:
      - When C(true), uploads the file every time and replaces the file on the CM.
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
  - Ravinder Reddy (@RavinderReddyF5)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Upload files to CM(Central Manager)
  cm_files:
    filename: "/path/to/file/file.json"
    description: "some file"
    timeout: 600

- name: Upload a file - force on
  cm_files:
    filename: "/path/to/file/file.json"
    description: "some file"
    force: "yes"

- name: Remove a file
  cm_files:
    filename: "/path/to/file/file.json"
    state: absent
'''

RETURN = r'''
filename:
  description: The path and filename of the file to be uploaded to CM.
  returned: changed
  type: str
  sample: "/path/to/file.tar"
name:
  description: The name of the file as it should appear on the CM.
  returned: changed
  type: str
  sample: "my_file.tar"
description:
  description: The description of the uploaded file as it should appear on the CM.
  returned: changed
  type: str
  sample: "this is my file"
'''
import os
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'description',
        'name',
        'filename',
    ]

    updatables = []


class ApiParameters(Parameters):
    pass


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
    pass


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
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

        self.create_on_device()
        return True

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
        if self.exists():
            raise F5ModuleError("File not deleted from CM.")
        return True

    def exists(self):
        uri = f"/v1/spaces/default/files?filter=file_name+eq+'{self.want.name}'"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message("No file found")
            return False

        if response['contents']['_embedded'].get('files'):
            self.file_uuid = response['contents']['_embedded']['files'][0]['id']
            self.log_message(f"File found: {self.file_uuid}")
            return True

    def create_on_device(self):
        form = {
            'content': {'filename': self.want.filename, "mime_type": "application/octet-stream"},
            'description': self.want.description,
            'file_name': self.want.name
        }
        self.log_message(f"Creating file {self.want.filename}")
        self.log_message(f"Form data: {form}")
        uri = '/api/v1/spaces/default/files'
        response = self.client.plugin.send_multipart(uri, form)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        interval, period = self.want.timeout
        return self.wait_for_file(interval, period)
        # self.log_message("File created successfully")
        # return True

    def remove_from_device(self):
        uri = f"/v1/spaces/default/files/{self.file_uuid}"
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        self.log_message("File deleted successfully")
        return True

    def wait_for_file(self, interval, period):
        for x in range(0, period):
            self.log_message(f"Waiting for API to register file, count: {x}", 'debug')
            if self.exists():
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
            name=dict(),
            description=dict(),
            filename=dict(
                type='path',
                required=True,
            ),
            force=dict(type='bool', default='no'),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
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
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
