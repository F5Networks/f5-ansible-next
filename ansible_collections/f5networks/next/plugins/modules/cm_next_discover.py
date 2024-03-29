#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_next_discover
short_description: Module to Add/Delete BIG-IP Next Instances onto Central Manager
description:
  - Module to Add/Discover/Delete C(BIG-IP-Next) Instances onto B(CM(Central Manager))
  - Instances to be added are not deployed through CM
version_added: 1.0.0
options:
  device_ip:
    description:
      - The ip address of the BIG-IP Next instance to discover and add under CM management.
    type: str
    required: True
  device_port:
    description:
      - The port on which CM can communicate with the BIG-IP Next instance.
    type: int
    default: 5443
  device_user:
    description:
      - The administrator username on the target BIG-IP Next instance.
    type: str
    required: True
  device_password:
    description:
      - The administrator password on the target BIG-IP Next instance.
    type: str
    required: True
  mgmt_user:
    description:
      - The username the CM uses to manage the target BIG-IP Next instance.
      - Parameter required when C(state) is C(present).
    type: str
  mgmt_password:
    description:
      - The password the CM uses to manage the target BIG-IP Next instance.
      - Parameter required when C(state) is C(present).
    type: str
  accept_untrusted:
    description:
      - Option to enable/disable untrusted certificates from discovered BIG-IP Next instances.
    type: bool
    default: false
  force:
    description:
      - When C(true), re-discovers managed existing BIG-IP Next instance by removing adding the device with the
        given C(device_ip).
      - When C(false), no device is added if a device with the same C(device_ip) exists.
    type: bool
    default: false
  timeout:
    description:
      - The amount of time to wait for the discover task to finish, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(present), ensures the BIG-IP Next instance is discovered and added under CM management.
      - When C(absent), ensures the BIG-IP Next instance is removed from CM management.
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
- name: Add BIG-IP Next instance
  cm_next_discover:
    device_ip: "10.1.1.8"
    device_port: 5443
    device_user: "admin"
    device_password: "Welcome123!"
    mgmt_user: 'admin-cm'
    mgmt_password: "Welcome123!"
    timeout: 600

- name: Add BIG-IP Next instance - force on
  cm_next_discover:
    device_ip: "10.1.1.8"
    device_port: 5443
    device_user: "admin"
    device_password: "Welcome123!"
    mgmt_user: 'admin-cm'
    mgmt_password: "Welcome123!"
    timeout: 600
    force: true

- name: Remove BIG-IP Next Instance
  cm_next_discover:
    device_ip: "10.1.1.8"
    device_user: "admin"
    device_password: "Welcome123!"
    state: 'absent'
    timeout: 600
'''

RETURN = r'''
device_ip:
  description: The ip address of the managed BIG-IP Next instance.
  returned: changed
  type: str
  sample: "192.168.1.1"
device_port:
  description: The port on which CM can communicate with the BIG-IP Next instance.
  returned: changed
  type: int
  sample: 5443
device_user:
  description: The administrator username on the target BIG-IP Next instance.
  returned: changed
  type: str
  sample: "admin"
mgmt_user:
  description: The username the CM uses to manage the target BIG-IP Next instance.
  returned: changed
  type: str
  sample: "admin-cm"
'''

import os
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.logging import sanitize_sensitive_data


class Parameters(AnsibleF5Parameters):
    api_map = {
        "address": "device_ip",
        "port": "device_port",
        "management_user": "mgmt_user",
        "management_password": "mgmt_password",
        "management_confirm_password": "mgmt_password"
    }

    api_attributes = [
        "address",
        "port",
        "device_user",
        "device_password",
        "management_user",
        "management_password",
        "management_confirm_password"
    ]

    returnables = [
        "device_ip",
        "device_port",
        "device_user",
        "device_password",
        "mgmt_user",
        "mgmt_password"
    ]

    updatables = []


class ModuleParameters(Parameters):
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
    returnables = [
        "device_ip",
        "device_port",
        "device_user",
        "mgmt_user",
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.device_uuid = None

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

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        return self.remove_from_device()

    def update(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        if self.want.force:
            # The process of updating is a removal and adding back the existing instance.
            self.remove_from_device()
            return self.create_on_device()
        return False

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        # self.check_if_device_reachable()
        return self.create_on_device()

    def exists(self):
        uri = f"/device/v1/inventory?filter=address+eq+'{self.want.device_ip}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('count', 0) == 0:
            self.log_message("No devices found")
            return False

        if response['contents']['count'] == 1:
            self.device_uuid = response['contents']['_embedded']['devices'][0]['id']
            self.log_message(f"Device UUID: {self.device_uuid}")
            return True
        else:
            self.log_message(
                f"Query returned more than 1 with the specified ip address: {self.want.device_ip}", 'error'
            )
            raise F5ModuleError(
                f"Query returned more than 1 with the specified ip address: "
                f"{self.want.device_ip} "
            )

    def check_if_device_reachable(self):
        uri = "/device/v1/instances/authenticate"
        params = dict(
            address=self.want.device_ip,
            port=self.want.device_port,
            username=self.want.device_user,
            password=self.want.device_password
        )
        self.log_message("Checking if device is reachable")
        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        response = self.client.post(uri, params)

        if response['code'] == 200:
            self.log_message("Device reachable")
            return True

        if response['code'] in [401, 500]:
            self.log_message(
                f"Reachability check failed with the following message: {response['contents']['message']}",
                'error'
            )
            raise F5ModuleError(
                f"Reachability check failed with the following message: {response['contents']['message']}"
            )

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

    def update_task_on_device(self, uri):
        self.log_message(f"Patching task to accept untrusted certificates: {uri}")
        payload = {"is_user_accepted_untrusted_cert": True}
        self.log_message(f"Patching payload: {payload}")
        response = self.client.patch(uri, body=payload)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])
        self.log_message("Task patched successfully.")
        return True

    def create_on_device(self):
        interval, period = self.want.timeout
        params = self.changes.api_params()
        uri = "/device/v1/inventory"

        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_url = f"/device/v1/discovery-tasks/{os.path.basename(response['contents']['path'])}"
        self.log_message("Discovery task created successfully")
        self.log_message(f"Discovery task url: {task_url}")
        if self.want.accept_untrusted:
            self.update_task_on_device(task_url)
        task = self.wait_for_task(task_url, interval, period)

        if task['status'] == 'failed':
            self.log_message(
                f"Discovery task failed with the following reason: {task['failure_reason']}", 'error'
            )
            raise F5ModuleError(f"Discovery task failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("Discovery task completed successfully")
            return True

    def wait_for_task(self, url, interval, period):
        for x in range(0, period):
            self.log_message(f"Retrieving task status, count: {x}", 'debug')
            task = self._check_task_on_device(url)
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

    def _check_task_on_device(self, uri):
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']

    def remove_from_device(self):
        interval, period = self.want.timeout
        params = dict(
            device_user=self.want.device_user,
            device_password=self.want.device_password,
        )

        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        uri = f"/device/v1/inventory/{self.device_uuid}"
        response = self.client.delete(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_url = f"/device/v1/deletion-tasks/{os.path.basename(response['contents']['path'])}"
        self.log_message("Removal task created successfully")
        self.log_message(f"Removal task url: {task_url}")
        task = self.wait_for_task(task_url, interval, period)

        if task['status'] == 'failed':
            self.log_message(
                f"Device removal failed with the following reason: {task['failure_reason']}", 'error'
            )
            raise F5ModuleError(f"Device removal failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("Device removal task completed successfully")
            return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            device_ip=dict(
                required=True
            ),
            device_port=dict(
                type='int',
                default=5443
            ),
            device_user=dict(
                required=True,
            ),
            device_password=dict(
                no_log=True,
                required=True
            ),
            accept_untrusted=dict(
                type='bool',
                default='no'
            ),
            mgmt_user=dict(),
            mgmt_password=dict(
                no_log=True
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            force=dict(
                type='bool',
                default='no'
            ),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['state', 'present', ['mgmt_user', 'mgmt_password']]
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        required_if=spec.required_if
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
