#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_backup_restore
short_description: Backup and restore CM configuration
description:
  - Backup and restore CM configuration.
version_added: "1.0.0"
options:
  encryption_password:
    description:
      - Encryption password for the backup to be created.
      - Password should be minimum of 8 characters.
    type: str
    required: true
  name:
    description:
      - The name of the backup file to be created while Scheduling a Backup.
      - Actual File Name is auto-generated in the case of Instant Backup.
    type: str
    required: true
  timeout:
    description:
      - The amount of time in seconds to wait for the backup or restore operation to complete.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  frequency:
    description:
      - Ensured that backup is scheduled Monthly, Weekly or Daily.
      - The accepted value is Monthly, Weekly, Daily.
    type: str
    choices:
      - Monthly
      - Weekly
      - Daily
  days_of_the_week_to_run:
    description:
      - Specifies Day of the week when backup has been scheduled. 0-Sunday, 1-Monday and so on.
      - The accepted value range is between C(0) and C(6).
    type: list
    elements: int
  day_of_the_month_to_run:
    description:
      - Specifies From which Day of the month backup should start.
    type: int
  scheduled:
    description:
      - When C(True), ensures that that scheduled backup is to be delete.
      - When C(False), ensures that that Instant backup is to be delete.
      - Scheduled Parameter is required when state is absent.
    type: bool
  state:
    description:
      - When C(backup), ensures the backup is file is created instantly.
      - When C(scheduled_backup), ensures the backup is file is scheduled.
      - When C(restore), ensures the target BIG-IP Next instance is restored from the given backup filename.
      - When C(absent), ensures the backup file is removed.
    type: str
    choices:
      - absent
      - backup
      - scheduled_backup
      - restore
    default: backup
  schedule:
    description:
      - Specifies whether backup is to be scheduled or not.
    type: dict
    suboptions:
      start_at:
        description:
          - Specifies Start time of the backup.
        type: str
      end_at:
        description:
          - Specifies End time of the backup.
        type: str
notes:
  - This module's operations are not idempotent.
author:
  - Prateek Ramani (@ramani)
'''


EXAMPLES = r'''
- name: Backup Central Manager instance
  cm_backup_restore:
    encryption_password: "F5site02"
    name: Backup-20240829-101240_L_20.3.0-0.14.14_6.tgz
    schedule:
      start_at: "2019-08-24T14:15:22Z"
    frequency: Weekly
    days_of_the_week_to_run: [0, 1]
    state: scheduled_backup
    timeout: 600

- name: Restore Central Manager instance
  cm_next_backup_restore:
    encryption_password: "F5site02"
    name: Backup-20240829-101240_L_20.3.0-0.14.14_6.tgz
    state: restore
    timeout: 600

- name: Remove a Central Manager backup
  cm_next_backup_restore:
    filename: Backup-20240829-101240_L_20.3.0-0.14.14_6.tgz
    scheduled: true
    state: absent
'''

RETURN = r'''
encryption_password:
  description: Encryption password for the backup to be created.
  returned: changed
  type: str
  sample: "F5site02"
name:
  description: The name of the backup file to be created.
  returned: changed
  type: str
  sample: "Backup-20240829"
frequency:
  description: Ensured that backup is scheduled Monthly, Weekly or Daily.
  returned: changed
  type: str
  sample: "Weekly"
state:
  description: Ensured whether its is a backup, scheduled backup or restore.
  returned: changed
  type: str
  sample: "backup"
days_of_the_week_to_run:
  description: Specifies Day of the week when backup has been scheduled. 0-Sunday, 1-Monday and so on.
  returned: changed
  type: list
  sample: [0,1,2]
day_of_the_month_to_run:
  description: Specifies From which Day of the month backup should start.
  returned: changed
  type: int
  sample: 15
'''

# import os
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters
)


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'encryption_password',
        'name',
        'frequency',
        'state'
        'days_of_the_week_to_run'
        'day_of_the_month_to_run'
    ]


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
        'frequency',
        'days_of_the_week_to_run',
        'day_of_the_month_to_run',
        'schedule'
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
        if state == "scheduled_backup":
            changed = self.scheduled_backup()
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
        return self.create()

    def scheduled_backup(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        exists, id = self.exists(True)
        if exists:
            uri = "/v1/system/backups/schedule/" + id
            return self.schedule_backup_target(uri, "PUT")
        else:
            uri = "/v1/system/backups/schedule"
            return self.schedule_backup_target(uri, "POST")

    def restore(self):
        return self.restore_target()

    def absent(self):
        exists, id = self.exists(self.want.schedule)
        if exists:
            return self.remove(id)

        return False

    def remove(self, id):
        if self.module.check_mode:  # pragma: no cover
            return True
        return self.remove_from_device(id)

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.backup_target()
        return True

    def schedule_backup_target(self, uri, method):
        form = {
            'encryption_password': self.want.encryption_password,
            'name': self.want.name,
        }

        if self.want.schedule:
            form['schedule'] = {}
            if 'start_at' not in self.want.schedule or self.want.schedule['start_at'] is None:
                raise F5ModuleError("Backup failed - Start At is required to schedule a backup")
            else:
                form['schedule']['start_at'] = self.want.schedule['start_at']

            if self.want.frequency is None:
                raise F5ModuleError("Backup failed - Frequency is required to schedule a backup")
            else:
                frequency = self.want.frequency
                if frequency == 'Weekly':
                    if self.want.days_of_the_week_to_run is None:
                        raise F5ModuleError("Backup failed - Days of the Week to Run is required when Frequency is Weekly")
                    else:
                        form['DaysOfTheWeek'] = {}
                        form['DaysOfTheWeek']['hourToRunOn'] = 10
                        form['DaysOfTheWeek']['minuteToRunOn'] = 30
                        form['DaysOfTheWeek']['interval'] = 1
                        if isinstance(self.want.days_of_the_week_to_run, list):
                            form['DaysOfTheWeek']['daysOfTheWeekToRun'] = form.get("list", [])
                            for item in self.want.days_of_the_week_to_run:
                                form['DaysOfTheWeek']['daysOfTheWeekToRun'].append(item)
                        else:
                            raise F5ModuleError("Backup failed - Days of the Week to Run should be List of Integers")
                        form['schedule_type'] = 'DaysOfTheWeek'
                elif frequency == 'Monthly':
                    if self.want.day_of_the_month_to_run is None:
                        raise F5ModuleError("Backup failed - Day of the Month to Run is required when Frequency is Monthly")
                    else:
                        form['DayAndTimeOfTheMonth'] = {}
                        form['DayAndTimeOfTheMonth']['hourToRunOn'] = 10
                        form['DayAndTimeOfTheMonth']['minuteToRunOn'] = 30
                        form['DayAndTimeOfTheMonth']['interval'] = 1
                        form['DayAndTimeOfTheMonth']['dayOfTheMonthToRun'] = int(self.want.day_of_the_month_to_run)
                        form['schedule_type'] = 'DayAndTimeOfTheMonth'
                else:
                    form['BasicWithInterval'] = {}
                    form['BasicWithInterval']['intervalToRun'] = 24
                    form['BasicWithInterval']['intervalUnit'] = 'HOUR'
                    form['schedule_type'] = 'BasicWithInterval'

            if self.want.schedule['end_at'] is not None:
                form['schedule']['end_at'] = self.want.schedule.end_at
        else:
            raise F5ModuleError("Backup failed - Schedule Time is required to schedule a backup")

        if method == "POST":
            response = self.client.post(uri, form)
        elif method == "PUT":
            response = self.client.put(uri, form)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("Backup Scheduled successfully")

        return True

    def exists(self, scheduled):
        return self.file_exists(scheduled)

    def file_exists(self, scheduled):
        if scheduled:
            uri = f"/system/v1/schedules?filter=name+eq+'{self.want.name}'"
        else:
            uri = f"/system/v1/files?filter=file_name+eq+%27{self.want.name}%27"
        response = self.client.get(uri)

        if response['code'] == 404:
            self.log_message("Specified file not found on device:" + self.want.name)
            return False, ''

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if '_embedded' in response['contents']:
            if scheduled and 'schedules' in response['contents']['_embedded']:
                self.log_message("Scheduled Backup found on device")
                return True, response['contents']['_embedded']['schedules'][0]['id']
            elif not scheduled and 'files' in response['contents']['_embedded']:
                self.log_message("Backup found on device")
                return True, response['contents']['_embedded']['files'][0]['id']
        else:
            return False, ''

    def backup_target(self):
        interval, period = self.want.timeout

        form = {
            'scheduled': False,
            'type': "light",
            'encryption_password': self.want.encryption_password,
            'name': self.want.name
        }

        uri = "/v1/system/backups"

        response = self.client.post(uri, form)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        pathList = response['contents']['path'].split('/')[-1]

        task_url = f"/v1/system/backup-tasks/{pathList}"

        self.log_message("Backup task created successfully")
        self.log_message("Backup task url: {task_url}")

        task = self.wait_for_task(task_url, interval, period)

        if task["_embedded"]["tasks"][0]['status'] == 'COMPLETED':
            self.log_message("Backup task completed successfully")
            return True

        elif task["_embedded"]["tasks"][0]['status'] == 'FAILED':
            self.log_message("Backup failed with the following reason:" + task['_embedded']['tasks'][0]['failure_reason'])
            raise F5ModuleError("Backup failed with the following reason:" + task["_embedded"]["tasks"][0]['failure_reason'])

    def restore_target(self):
        # params = self.changes.api_params()
        interval, period = self.want.timeout
        uri = "/v1/system/backups"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        file_id = ''
        if '_embedded' in response['contents'] and 'backups' in response['contents']['_embedded']:
            for backup in response['contents']['_embedded']['backups']:
                if backup['file_name'] == self.want.name:
                    file_id = backup['file_id']

        if file_id == '':
            raise F5ModuleError("Restore failed - Backup File not found")

        form = {
            'encryption_password': self.want.encryption_password,
            'file_id': file_id
        }

        uri = "/v1/system/restore"

        response = self.client.post(uri, form)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_url = "/v1/system/restore-tasks/"
        self.log_message("Restore task created successfully.")
        self.log_message("Restore task url:" + task_url)

        task = self.wait_for_task(task_url, interval, period)

        if task["_embedded"]["tasks"][0]['status'] == 'FAILED':
            self.log_message("Restore failed with the following reason:" + task["_embedded"]["tasks"][0]['failure_reason'])
            raise F5ModuleError("Restore failed with the following reason:" + task["_embedded"]["tasks"][0]['failure_reason'])

        if task["_embedded"]["tasks"][0]['status'] == 'COMPLETED':
            self.log_message("Restore task completed successfully")
            return True

    def wait_for_task(self, url, interval, period):
        for x in range(0, period):
            task = self._check_task_on_device(url)
            if '_embedded' in task and task["_embedded"]["tasks"][0]['status'] == 'COMPLETED':
                self.log_message("Task COMPLETED")
                return task
            elif '_embedded' in task and task["_embedded"]["tasks"][0]['status'] == 'FAILED':
                self.log_message("Task Failed")
                return task
            self.log_message(f"Pausing for {interval}")
            time.sleep(interval)
        self.log_message("Module timed out, waiting for task to finish", 'error')
        raise F5ModuleError(
            "Module timeout reached, state change is unknown, "
            "please increase the timeout parameter for long lived actions."
        )

    def _check_task_on_device(self, uri):
        response = self.client.get(uri)
        managed_error = 'unknown error from message catalog ID SHARED-00001'
        if response['code'] in [200, 201, 202] or (response['code'] == 500 and 'contents' in response and managed_error in response['contents']):
            return response['contents']
        raise F5ModuleError(response['contents'])

    def remove_from_device(self, id):
        if self.want.schedule:
            uri = f'/v1/system/backups/schedule/{id}'
        else:
            uri = f'/system/v1/files/{id}'
        response = self.client.delete(uri)
        if response['code'] not in [200, 201, 202, 204]:
            raise F5ModuleError(response['contents'])

        self.log_message("File removed from device", 'info')
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                type='str',
                required=True
            ),
            encryption_password=dict(
                type='str',
                required=True,
                no_log=True
            ),
            frequency=dict(
                type='str',
                choices=['Weekly', 'Daily', 'Monthly']
            ),
            scheduled=dict(
                type='bool'
            ),
            days_of_the_week_to_run=dict(
                type='list',
                elements='int'
            ),
            day_of_the_month_to_run=dict(
                type='int'
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            schedule=dict(
                type='dict',
                options=dict(
                    start_at=dict(),
                    end_at=dict(),
                ),
            ),
            state=dict(
                default='backup',
                choices=['backup', 'restore', 'absent', 'scheduled_backup']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = []
        self.required_if = [
            ['state', 'absent', ['name', 'scheduled']],
            ['state', 'backup', ['name', 'encryption_password'], True],
            ['state', 'backup', ['name', 'encryption_password', 'schedule', 'frequency'], True],
            ['state', 'restore', ['name', 'encryption_password'], True],
            ['frequency', 'Weekly', ['name', 'encryption_password', 'schedule', 'days_of_the_week_to_run'], True],
            ['frequency', 'Monthly', ['name', 'encryption_password', 'schedule', 'day_of_the_month_to_run'], True],
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
        # required_if=spec.required_if
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
