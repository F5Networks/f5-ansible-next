#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_next_upgrade
short_description: Manage NEXT instance upgrades through CM
description:
  - Manage NEXT instance upgrades through CM.
version_added: "1.0.0"
options:
  device_hostname:
    description:
      - The hostname of the Next instance to be upgraded.
      - Parameter mutually exclusive with C(device_ip).
    type: str
  device_ip:
    description:
      - The ip address of the Next instance to be upgraded.
      - Parameter mutually exclusive with C(device_hostname).
    type: str
  filename:
    description:
      - The filename of the uploaded image on Next instance.
    type: str
    required: True
  sig_filename:
    description:
      - The filename of the uploaded signature file on the Next instance.
    type: str
    required: True
  type:
    description:
      - The type of next instance to be upgraded.
    type: str
    default: ve
    choices:
      - ve
  timeout:
    description:
      - The amount of time in seconds to wait for the Next upgrade to complete.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
notes:
  - This module is not yet idempotent.
  - Module requires upgrade images to be present on the target Next instance.
author:
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- hosts: all
  collections:
    - f5networks.next
  connection: httpapi

  vars:
    ansible_host: "lb.mydomain.com"
    ansible_user: "admin"
    ansible_httpapi_password: "secret"
    ansible_network_os: f5networks.next.cm
    ansible_httpapi_use_ssl: yes

  tasks:
    - name: Upgrade Next instance
      cm_next_upgrade:
        device_ip: "10.1.1.11"
        filename: "BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz"
        sig_filename: "BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz.512.sig"
        timeout: 600
'''

RETURN = r'''
device_hostname:
  description: The hostname of the Next instance to be upgraded.
  returned: changed
  type: str
  sample: "foo.bar.net"
device_ip:
  description: The ip address of the Next instance to be upgraded.
  returned: changed
  type: str
  sample: "192.168.1.1"
filename:
  description: The filename of the uploaded image on Next instance.
  returned: changed
  type: str
  sample: "BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz"
sig_filename:
  description: The filename of the uploaded signature file on the Next instance.
  returned: changed
  type: str
  sample: "BIG-IP-Next-0.14.0-2.45.3+0.0.24.tgz.512.sig"
'''
import os
import re
import time
import traceback

from ansible.module_utils.basic import (
    AnsibleModule, missing_required_lib
)
from ansible.module_utils.connection import Connection

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)
from ..module_utils.client import F5Client
from ..module_utils.logging import sanitize_sensitive_data

try:
    from packaging.version import Version
except ImportError:  # pragma: no cover
    HAS_PACKAGING = False
    Version = None
    PACKAGING_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_PACKAGING = True
    PACKAGING_IMPORT_ERROR = None


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'version',
        'device_hostname',
        'device_ip',
        'filename',
        'sig_filename',
    ]

    updatables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def version(self):
        pattern = re.compile(r'BIG-IP-Next-(\d+\.\d+\.\d+)(?:[+-]\d+\.\d+\.\d+)?(?:\.tgz)?(?:\.\d+\.sig)?')
        match = pattern.search(self._values['filename'])
        if match:
            version = match.group(1)
            return version

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
        self.have = ApiParameters()
        self.device_uuid = None
        self.current_version = None

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
        result = dict()

        changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def present(self):
        if self.can_be_upgraded():
            return self.upgrade()
        return False

    def upgrade(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.upgrade_target()
        return True

    def can_be_upgraded(self):
        device_exists = self.device_exists()
        if device_exists:
            if Version(self.want.version) > Version(self.current_version):
                return True
            return False
        return False

    def device_exists(self):
        if self.want.device_ip:
            uri = f"/device/v1/inventory?filter=address+eq+'{self.want.device_ip}'"
        else:
            uri = f"/device/v1/inventory?filter=hostname+eq+'{self.want.device_hostname}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('count', 0) == 0:
            self.log_message(
                f"Specified device: {self.want.device_ip if self.want.device_ip else self.want.device_hostname}, "
                f"not found.", 'error'
            )
            raise F5ModuleError(
                f"Specified device: {self.want.device_ip if self.want.device_ip else self.want.device_hostname}"
                f", not found.")

        if response['contents']['count'] == 1:
            self.device_uuid = response['contents']['_embedded']['devices'][0]['id']
            self.current_version = response['contents']['_embedded']['devices'][0]['version']
            self.log_message(f"Device UUID: {self.device_uuid}")
            self.log_message(f"Device Version: {self.current_version}")
            return True
        else:
            self.log_message(
                f"Query returned more than 1 device with the specified property: "
                f"{self.want.device_ip if self.want.device_ip else self.want.device_hostname}", 'error'
            )
            raise F5ModuleError(
                f"Query returned more than 1 device with the specified property: "
                f"{ self.want.device_ip if self.want.device_ip else self.want.device_hostname} "
            )

    def list_files_on_target_device(self):
        uri = f"/device/v1/proxy/{self.device_uuid}?path=/files"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if any([response['contents'].get('count', 0) == 0, not response['contents'].get('_embedded')]):
            self.log_message("No files found on upgrade target, upgrade aborted.", 'error')
            raise F5ModuleError('No files found on upgrade target, upgrade aborted.')

        self.log_message(
            f"Configuration read from device: "
            f"{sanitize_sensitive_data(response['contents'], self.client.to_obfuscate())}"
        )
        return response['contents']['_embedded'].get('files', [])

    def get_files_ids(self):
        sig_id = None
        file_id = None
        files = self.list_files_on_target_device()
        for file in files:
            if self.want.filename == file['fileName']:
                file_id = os.path.basename(file['uri'])
            elif self.want.sig_filename == file['fileName']:
                sig_id = os.path.basename(file['uri'])
        if file_id is None:
            self.log_message(f"The given filename: {self.want.filename} "
                             f"has not been found on upgrade target.", 'error'
                             )
            raise F5ModuleError(
                f"The given filename: {self.want.filename} has not been found on upgrade target."
            )
        if sig_id is None:
            self.log_message(f"The given sig_filename: {self.want.sig_filename} "
                             f"has not been found on upgrade target.", 'error'
                             )
            raise F5ModuleError(
                f"The given sig_filename: {self.want.sig_filename} has not been found on upgrade target."
            )
        return file_id, sig_id

    def upgrade_target(self):
        interval, period = self.want.timeout
        uri = f"/device/v1/inventory/{self.device_uuid}/upgrade"
        filename, signature = self.get_files_ids()
        payload = dict(image_name=filename, upgrade_type=self.want.type, signature_name=signature)

        self.log_message(
            f"Processed parameters: {sanitize_sensitive_data(payload, self.client.to_obfuscate())}"
        )

        response = self.client.post(uri, payload)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = os.path.basename(response['contents']['path'])

        self.log_message("Next instance upgrade task created successfully")
        self.log_message(f"Task ID: {task_id}")

        task = self.wait_for_task(task_id, interval, period)

        if task['status'] == 'failed':
            self.log_message(
                f"Upgrade failed with the following reason: {task['failure_reason']}", 'error'
            )
            raise F5ModuleError(f"Upgrade failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("Upgrade task completed successfully")
            return True

    def wait_for_task(self, task_id, interval, period):
        for x in range(0, period):
            self.log_message(f"Retrieving task status, count: {x}", 'debug')
            task = self._check_task_on_device(task_id)
            if task['status'] != 'running':
                self.log_message("Task stopped running")
                return task
            self.log_message(f"Pausing for {interval}", 'debug')
            time.sleep(interval)
        self.log_message("Module timed out, waiting for task to finish", 'error')
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _check_task_on_device(self, task_id):
        uri = f"/device/v1/upgrade-tasks?filter=id+eq+'{task_id}'"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']['_embedded']['tasks'][0]


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            device_hostname=dict(),
            device_ip=dict(),
            type=dict(
                default='ve',
                choices=['ve']
            ),
            filename=dict(
                required=True,
            ),
            sig_filename=dict(
                required=True,
            ),
            timeout=dict(
                type='int',
                default=300
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

    if not HAS_PACKAGING:
        module.fail_json(
            msg=missing_required_lib('packaging'),
            exception=PACKAGING_IMPORT_ERROR
        )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
