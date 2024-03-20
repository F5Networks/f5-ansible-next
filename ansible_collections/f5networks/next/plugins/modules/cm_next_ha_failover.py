#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_next_ha_failover
short_description: Fail-over Next HA instance on CM
description:
  - Force fail-over a NEXT has instance managed by CM.
version_added: 1.0.0
options:
  ha_hostname:
    description:
      - The hostname of the HA Next instance.
      - Parameter mutually exclusive with C(ha_ip).
    type: str
  ha_ip:
    description:
      - The ip address of the HA Next instance.
      - Parameter mutually exclusive with C(ha_hostname).
    type: str
  active_unit_hostname:
    description:
      - The hostname of the NEXT unit in HA pair to be made active.
      - Parameter mutually exclusive with C(active_unit_ip).
    type: str
  active_unit_ip:
    description:
      - The ip address of the NEXT unit in HA pair to be made active.
      - Parameter mutually exclusive with C(active_unit_hostname).
    type: str
  timeout:
    description:
      - The amount of time to wait for the HA failover task to finish, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
author:
  - Ravinder Reddy (@RavinderReddyF5)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
- name: Failover HA pair using IP address
  cm_next_ha_failover:
    ha_ip: "172.16.2.1"
    active_unit_ip: "172.16.1.1"
    timeout: 600

- name: Failover HA pair using hostname and ip
  cm_next_ha_failover:
    ha_hostname: "foo.bar.net"
    active_unit_ip: "172.16.1.1"
    timeout: 600
'''

RETURN = r'''

active_unit_hostname:
  description: The hostname of the NEXT unit in HA pair that is active.
  returned: changed
  type: str
  sample: "unit1.bar.net"
active_unit_ip:
  description: The ip address of the NEXT unit in HA pair that is active.
  returned: changed
  type: str
  sample: "10.1.16.1"
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
    api_map = {}

    api_attributes = []

    returnables = [
        'active_unit_ip',
        'active_unit_hostname',
    ]

    updatables = [
        'active_unit_ip',
        'active_unit_hostname',
    ]


class ApiParameters(Parameters):
    @property
    def active_unit_ip(self):
        for node in self._values.get('nodes', []):
            if node['state'] == 'ACTIVE':
                return node['address']

    @property
    def active_unit_hostname(self):
        for node in self._values.get('nodes', []):
            if node['state'] == 'ACTIVE':
                return node['hostname']


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
    pass


class Difference(object):  # pragma: no cover
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
        except AttributeError:
            return attr1


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.ha_uuid = None

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
        result = dict()

        changed = self.execute()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def execute(self):
        self.ha_exists()
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def ha_exists(self):
        if self.want.ha_ip:
            uri = f"/device/v1/inventory?filter=address+eq+'{self.want.ha_ip}'"
        else:
            uri = f"/device/v1/inventory?filter=hostname+eq+'{self.want.ha_hostname}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('count', 0) == 0:
            self.log_message(
                f"Specified HA instance: {self.want.ha_ip if self.want.ha_ip else self.want.ha_hostname} "
                f"is not managed by CM.", 'error'
            )
            raise F5ModuleError(
                f"Specified HA instance: {self.want.ha_ip if self.want.ha_ip else self.want.ha_hostname}"
                f", is not managed by CM.")

        if response['contents']['count'] == 1:
            if response['contents']['_embedded']['devices'][0]['mode'] == 'HA':
                self.ha_uuid = response['contents']['_embedded']['devices'][0]['id']
                self.log_message(f"Found HA cluster: {self.ha_uuid}")
                return True
            self.log_message(
                f"The specified Next instance: {self.want.ha_ip if self.want.ha_ip else self.want.ha_hostname} "
                f"does not seem to be running in HA mode.", 'error'
            )
            raise F5ModuleError(f"The specified Next instance: "
                                f"{self.want.ha_ip if self.want.ha_ip else self.want.ha_hostname} does not seem to be "
                                f"running in HA mode."
                                )
        else:
            self.log_message(
                f"Query returned more than 1 HA instance with the specified property: "
                f"{self.want.ha_ip if self.want.ha_ip else self.want.ha_hostname} ", 'error'
            )
            raise F5ModuleError(
                f"Query returned more than 1 HA instance with the specified property: "
                f"{self.want.ha_ip if self.want.ha_ip else self.want.ha_hostname} "
            )

    def update_on_device(self):
        interval, period = self.want.timeout
        uri = f"/device/v1/inventory/{self.ha_uuid}/ha/failover"

        response = self.client.post(uri, {})

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = os.path.basename(response['contents']['path'])

        self.log_message("Failover task created successfully")
        self.log_message(f"Task ID: {task_id}")

        task = self.wait_for_task(task_id, interval, period)

        if task['status'] == 'failed':
            self.log_message(
                f"Failover failed with the following reason: {task['failure_reason']}", 'error'
            )
            raise F5ModuleError(f"Failover failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("Failover completed successfully")
            return True

    def read_current_from_device(self):
        uri = f"/device/v1/inventory/{self.ha_uuid}/health"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message(
            f"Configuration read from device: "
            f"{sanitize_sensitive_data(response['contents'], self.client.to_obfuscate())}"
        )
        return ApiParameters(params=dict(nodes=response['contents']['nodes']))

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
        uri = f"/device/v1/ha-failover-tasks/{task_id}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            ha_hostname=dict(),
            ha_ip=dict(),
            active_unit_ip=dict(),
            active_unit_hostname=dict(),
            timeout=dict(
                type='int',
                default=300
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive = [
            ['ha_hostname', 'ha_ip'],
            ['active_unit_hostname', 'active_unit_ip']
        ]
        self.required_one_of = [
            ['ha_hostname', 'ha_ip'],
            ['active_unit_hostname', 'active_unit_ip']
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
