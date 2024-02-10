#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_next_backup_restore
short_description: Backup and restore NEXT instance configration through CM
description:
  - Backup and restore NEXT instance configration through CM, manage backup files on CM.
version_added: "1.0.0"
options:
  device_hostname:
    description:
      - The hostname of the Next instance to back up config on.
      - Parameter mutually exclusive with C(device_ip).
      - The parameter is required when C(state) is C(backup) or C(restore).
    type: str
  device_ip:
    description:
      - The ip address of the Next instance to back up config on.
      - Parameter mutually exclusive with C(device_hostname).
      - The parameter is required when C(state) is C(backup) or C(restore).
    type: str
  filename:
    description:
      - The name of the file to save the Next instance backup.
      - System automatically appends .tar.gz extension to filenames provided without it.
    type: str
  file_password:
    description:
      - The encryption password for the given backup file as defined in C(filename).
      - The parameter is required when C(state) is C(backup) or C(restore).
    type: str
  timeout:
    description:
      - The amount of time in seconds to wait for the backup or restore operation to complete.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  force:
    description:
      - When C(true), removes the existing backup file and creates new one on the CM.
      - When C(false), no backup is created if a file with given name exists.
    type: bool
    default: false
  state:
    description:
      - When C(backup), ensures the backup is file is created.
      - When C(restore), ensures the target Next instance is restored from the given backup filename.
      - When C(absent), ensures the backup file is removed.
    type: str
    choices:
      - absent
      - backup
      - restore
    default: backup
notes:
  - This module's restore operation is not idempotent.
author:
  - Wojciech Wypior (@wojtek0806)
'''


EXAMPLES = r'''
- name: Backup Next instance
  cm_next_backup_restore:
    device_ip: "127.1.1.1"
    filename: "ansible_test.tar.gz"
    file_password: "pass123!"
    state: backup
    timeout: 600

- name: Backup a file - force on
  cm_next_backup_restore:
    device_ip: "127.1.1.1"
    filename: "ansible_test.tar.gz"
    file_password: "pass123!"
    state: backup
    force: "yes"
    timeout: 600

- name: Restore Next instance
  cm_next_backup_restore:
    device_ip: "127.1.1.1"
    filename: "ansible_test.tar.gz"
    file_password: "pass123!"
    state: restore
    timeout: 600

- name: Remove a file
  cm_next_backup_restore:
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
  description: The name of the file to save the Next instance backup.
  returned: changed
  type: str
  sample: "file.tar.gz"
'''

import os
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, remove_extensions
)
from ..module_utils.logging import sanitize_sensitive_data


class Parameters(AnsibleF5Parameters):
    api_map = {
        'encryption_password': 'file_password',
        'file_name': 'filename'
    }

    api_attributes = [
        'file_name',
        'encryption_password'
    ]

    returnables = [
        'filename',
        'file_password',
        'device_ip',
        'device_hostname'
    ]

    updatables = []


class ModuleParameters(Parameters):
    @property
    def filename(self):
        if self._values['filename'] is None:
            return None
        if not self._values['filename'].endswith('.tar.gz'):
            return self._values['filename'] + '.tar.gz'
        return self._values['filename']

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
        'filename',
        'device_ip',
        'device_hostname'
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

        if state == "backup":
            changed = self.backup()
        elif state == "restore":
            changed = self.restore()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def backup(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def restore(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        if self.exists():
            return self.restore_target()
        return False

    def absent(self):
        if self.file_exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        if self.file_exists():
            raise F5ModuleError("Backup file not removed from CM.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.backup_target()
        return True

    def update(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        if self.want.force:
            # The process of updating is a forced re-creation of a backup file.
            self.remove_from_device()
            return self.create()
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
            self.log_message(f"Device UUID: {self.device_uuid}")
            return True
        else:
            self.log_message(
                f"Query returned more than 1 device with the specified property: "
                f"{self.want.device_ip if self.want.device_ip else self.want.device_hostname}", 'error'
            )
            raise F5ModuleError(
                f"Query returned more than 1 device with the specified property: "
                f"{self.want.device_ip if self.want.device_ip else self.want.device_hostname}"
            )

    def exists(self):
        if self.device_exists():
            return self.file_exists()

    def file_exists(self):
        uri = f"/device/v1/backups/{self.want.filename}"
        response = self.client.get(uri)

        if response['code'] == 404:
            self.log_message(f"Specified file not found on device: {self.want.filename}")
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("File found on device")
        return True

    def backup_target(self):
        params = self.changes.api_params()
        interval, period = self.want.timeout
        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        # this is a workaround for the CM bug where it auto appends .tar.gz to any filename we provide, this results in
        # filenames like .tar.gz.tar.gz if user provides .tar.gz in their filename causing idempotency failure
        params['file_name'] = remove_extensions(params['file_name'])

        self.log_message(f"Changed filename: {params['file_name']}")

        uri = f"/device/v1/inventory/{self.device_uuid}/backup"

        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_url = f"/device/v1/backup-tasks/{os.path.basename(response['contents']['path'])}"
        self.log_message("Backup task created successfully")
        self.log_message(f"Backup task url: {task_url}")

        task = self.wait_for_task(task_url, interval, period)

        if task['status'] == 'failed':
            self.log_message(f"Backup failed with the following reason: {task['failure_reason']}", 'error')
            raise F5ModuleError(f"Backup failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("Backup task completed successfully")
            return True

    def restore_target(self):
        params = self.changes.api_params()
        interval, period = self.want.timeout
        uri = f"/device/v1/inventory/{self.device_uuid}/restore"

        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_url = f"/device/v1/restore-tasks/{os.path.basename(response['contents']['path'])}"
        self.log_message("Restore task created successfully.")
        self.log_message(f"Restore task url: {task_url}")

        task = self.wait_for_task(task_url, interval, period)

        if task['status'] == 'failed':
            self.log_message(f"Restore failed with the following reason: {task['failure_reason']}", 'error')
            raise F5ModuleError(f"Restore failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("Restore task completed successfully")
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
        uri = f"/device/v1/backups/{self.want.filename}"
        response = self.client.delete(uri)

        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        self.log_message("Backup file removed from device", 'info')
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            device_hostname=dict(),
            device_ip=dict(),
            filename=dict(),
            file_password=dict(
                no_log=True
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            force=dict(type='bool', default='no'),
            state=dict(
                default='backup',
                choices=['backup', 'restore', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['device_hostname', 'device_ip']
        ]
        self.required_if = [
            ['state', 'absent', ['filename']],
            ['state', 'backup', ['filename', 'file_password', 'device_hostname', 'device_ip'], True],
            ['state', 'restore', ['filename', 'file_password', 'device_hostname', 'device_ip'], True]
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
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
