#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_next_ha
short_description: Configure High Availability for NEXT instances.
description:
  - Configure High Availability for NEXT instances managed by CM.
version_added: 1.0.0
options:
  ha_name:
    description:
      - The name of the High Availability (HA) cluster.
    type: str
    required: True
  ha_ip:
    description:
      - The desired management IP of the HA cluster.
    type: str
    required: True
  active_node_ip:
    description:
      - The designated active Next instance management IP.
    type: str
    required: True
  standby_node_ip:
    description:
      - The designated standby Next instance management IP.
    type: str
    required: True
  active_node_control_plane_ip:
    description:
      - The HA control plane IP address on active node.
    type: str
    required: True
  standby_node_control_plane_ip:
    description:
      - The HA control plane IP address on standby node.
    type: str
    required: True
  control_plane_vlan:
    description:
      - The VLAN for the HA control plane.
    type: str
    required: True
  control_plane_vlan_tag:
    description:
      - The tag for the HA control plane VLAN.
      - If not defined the 0 tag is assumed.
    type: int
  active_node_data_plane_ip:
    description:
      - The HA data plane IP address on active node.
    type: str
    required: True
  standby_node_data_plane_ip:
    description:
      - The HA data plane IP address on standby node.
    type: str
    required: True
  data_plane_vlan:
    description:
      - The VLAN for the HA data plane.
    type: str
    required: True
  data_plane_vlan_tag:
    description:
      - The tag for the HA control plane VLAN.
      - If not defined the 0 tag is assumed.
    type: int
  external:
    description:
      - Configuration for the external network.
    type: dict
    suboptions:
      network_name:
        description:
          - The name of the external network.
        type: str
      vlan:
        description:
          - The VLAN for the external network.
        type: str
      tag:
        description:
          - The tag for the external network VLAN.
        type: int
      floating_ip:
        description:
          - The floating IP for the external network.
        type: str
      active_ip:
        description:
          - The active instance IP for the external network.
        type: str
      standby_ip:
        description:
          - The standby instance IP for the external network.
        type: str
  internal:
    description:
      - Configuration for the internal network.
    type: dict
    suboptions:
      network_name:
        description:
          - The name of the internal network.
        type: str
      vlan:
        description:
          - The VLAN for the internal network.
        type: str
      tag:
        description:
          - The tag for the internal network VLAN.
        type: int
      floating_ip:
        description:
          - The floating IP for the internal network.
        type: str
      active_ip:
        description:
          - The active instance IP for the internal network.
        type: str
      standby_ip:
        description:
          - The standby instance IP for the internal network.
        type: str
  timeout:
    description:
      - The amount of time to wait for the HA creation task to finish, in
        seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
author:
  - Wojciech Wypior (@wojtek0806)

'''

EXAMPLES = r'''
- name: Create HA NEXT instance on CM
  cm_next_ha:
    ha_name: 'demoha'
    ha_ip: '10.11.11.20'
    active_node_ip: '10.20.20.21'
    standby_node_ip: '10.20.20.22'
    control_plane_vlan: 'ha-cp-vlan'
    control_plane_vlan_tag: 100
    data_plane_vlan: 'ha-dp-vlan'
    data_plane_vlan_tag: 101
    active_node_data_plane_ip: '172.16.0.10/16'
    active_node_control_plane_ip: '10.11.11.21/16'
    standby_node_data_plane_ip: '172.16.0.11/16'
    standby_node_control_plane_ip: '10.11.11.22/16'
    external:
      network_name: 'DemoVlan115'
      vlan: 'external-ha-vlan'
      tag: 150
      floating_ip: '10.13.0.20/16'
      active_ip: '10.13.0.21/16'
      standby_ip: '10.13.0.22/16'
    internal:
      network_name: 'DemoVlan114'
      vlan: 'internal-ha-vlan'
      tag: 160
      floating_ip: '10.13.0.30/16'
      active_ip: '10.13.0.31/16'
      standby_ip: '10.13.0.32/16'
'''

RETURN = r'''
ha_name:
  description: The name of the High Availability (HA) cluster.
  returned: changed
  type: str
  sample: "myHA"
ha_ip:
  description: The management IP of the High Availability (HA) cluster.
  returned: changed
  type: str
  sample: "192.168.1.1"
active_node_ip:
  description: The management IP of the active NEXT instance.
  returned: changed
  type: str
  sample: "192.168.10.1"
standby_node_ip:
  description: The management IP of the standby NEXT instance.
  returned: changed
  type: str
  sample: "192.168.10.1"
control_plane_vlan:
  description: The vlan for the HA control plane.
  returned: changed
  type: str
  sample: "ha-cp-demo"
control_plane_vlan_tag:
  description: The vlan tag for the HA control plane.
  returned: changed
  type: int
  sample: 100
data_plane_vlan:
  description: The vlan for the HA data plane.
  returned: changed
  type: str
  sample: "ha-cp-demo"
data_plane_vlan_tag:
  description: The vlan tag for the HA data plane.
  returned: changed
  type: int
  sample: 100
active_node_data_plane_ip:
  description: The HA data plane IP address on active node.
  returned: changed
  type: str
  sample: "10.1.1.1"
active_node_control_plane_ip:
  description: The HA control plane IP address on active node.
  returned: changed
  type: str
  sample: "11.1.1.1"
standby_node_data_plane_ip:
  description: The HA data plane IP address on standby node.
  returned: changed
  type: str
  sample: "10.1.1.2"
standby_node_control_plane_ip:
  description: The HA control plane IP address on standby node.
  returned: changed
  type: str
  sample: "11.1.1.2"
floating_external_ip:
  description: The floating IP for the external network.
  returned: changed
  type: str
  sample: "172.16.1.20"
floating_internal_ip:
  description: The floating IP for the internal network.
  returned: changed
  type: str
  sample: "172.16.2.20"
external_network_name:
  description: The name of the external network.
  returned: changed
  type: str
  sample: "DEMOVLAN123"
external_vlan:
  description: The VLAN for the external network.
  returned: changed
  type: str
  sample: "ext-vlan"
external_vlan_tag:
  description: The VLAN tag for the external network.
  returned: changed
  type: int
  sample: 200
active_node_external_ip:
  description: The active instance IP for the external network.
  returned: changed
  type: str
  sample: "172.16.1.21"
standby_node_external_ip:
  description: The standby instance IP for the external network.
  returned: changed
  type: str
  sample: "172.16.1.22"
internal_network_name:
  description: The name of the internal network.
  returned: changed
  type: str
  sample: "DEMOVLAN345"
internal_vlan:
  description: The VLAN for the internal network.
  returned: changed
  type: str
  sample: "int-vlan"
internal_vlan_tag:
  description: The VLAN tag for the internal network.
  returned: changed
  type: int
  sample: 300
active_node_internal_ip:
  description: The active instance IP for the internal network.
  returned: changed
  type: str
  sample: "172.16.2.21"
standby_node_internal_ip:
  description: The standby instance IP for the internal network.
  returned: changed
  type: str
  sample: "172.16.2.22"
'''
import os
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)
from ..module_utils.templates.ha import vsphere
from ..module_utils.logging import sanitize_sensitive_data


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'ha_name',
        'ha_ip',
        'active_node_ip',
        'standby_node_ip',
        'control_plane_vlan',
        'control_plane_vlan_tag',
        'data_plane_vlan',
        'data_plane_vlan_tag',
        'active_node_data_plane_ip',
        'active_node_control_plane_ip',
        'standby_node_data_plane_ip',
        'standby_node_control_plane_ip',
        'floating_external_ip',
        'floating_internal_ip',
        'external_network_name',
        'external_vlan',
        'external_vlan_tag',
        'active_node_external_ip',
        'standby_node_external_ip',
        'internal_network_name',
        'internal_vlan',
        'internal_vlan_tag',
        'active_node_internal_ip',
        'standby_node_internal_ip'
    ]

    updatables = []


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def floating_external_ip(self):
        return self._values['external'].get('floating_ip')

    @property
    def floating_internal_ip(self):
        return self._values['internal'].get('floating_ip')

    @property
    def external_network_name(self):
        return self._values['external'].get('network_name')

    @property
    def external_vlan(self):
        return self._values['external'].get('vlan')

    @property
    def external_vlan_tag(self):
        return self._values['external'].get('tag')

    @property
    def active_node_external_ip(self):
        return self._values['external'].get('active_ip')

    @property
    def standby_node_external_ip(self):
        return self._values['external'].get('standby_ip')

    @property
    def internal_network_name(self):
        return self._values['internal'].get('network_name')

    @property
    def internal_vlan(self):
        return self._values['internal'].get('vlan')

    @property
    def internal_vlan_tag(self):
        return self._values['internal'].get('tag')

    @property
    def active_node_internal_ip(self):
        return self._values['internal'].get('active_ip')

    @property
    def standby_node_internal_ip(self):
        return self._values['internal'].get('standby_ip')

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
        if self.exists():
            return False
        else:
            return self.create()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = f"/device/v1/inventory?filter=address+eq+'{self.want.ha_ip}'"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('count', 0) == 0:
            self.log_message("HA cluster not found")
            return False

        if response['contents']['count'] == 1:
            if response['contents']['_embedded']['devices'][0]['mode'] == 'STANDALONE':
                self.log_message(
                    f"Specified HA Cluster IP address is in use by a STANDALONE instance: {self.want.ha_ip}",
                    'error'
                )
                raise F5ModuleError(
                    f"Specified HA Cluster IP address is in use by a STANDALONE instance: {self.want.ha_ip}.")
            if response['contents']['_embedded']['devices'][0]['mode'] == 'HA':
                self.log_message(f"Found HA cluster: {self.want.ha_ip}")
                return True

    def _get_node_uuid(self, ip):
        uri = f"/device/v1/inventory?filter=address+eq+'{ip}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('count', 0) == 0:
            self.log_message(f"Specified node IP: {ip}, is not managed by CM.", 'error')
            raise F5ModuleError(f"Specified node IP: {ip}, is not managed by CM.")

        if response['contents']['count'] == 1:
            self.log_message(f"Found node UUID: {response['contents']['_embedded']['devices'][0]['id']}")
            return response['contents']['_embedded']['devices'][0]['id']
        else:
            self.log_message(
                f"Query returned more than 1 standby node with the specified ip address: {ip}", 'error'
            )
            raise F5ModuleError(
                f"Query returned more than 1 standby node with the specified ip address: "
                f"{ip} "
            )

    def create_on_device(self):
        interval, period = self.want.timeout
        params = self.changes.to_return()
        params['standby_uuid'] = self._get_node_uuid(self.want.standby_node_ip)
        self.log_message(
            f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}"
        )
        output = process_json(params, vsphere)

        self.log_message(
            f"Generated JSON: {sanitize_sensitive_data(output, self.client.to_obfuscate())}"
        )
        uri = f"/device/v1/inventory/{self._get_node_uuid(self.want.active_node_ip)}/ha"

        response = self.client.post(uri, output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = os.path.basename(response['contents']['path'])

        self.log_message("HA creation task created successfully")
        self.log_message(f"Task ID: {task_id}")

        task = self.wait_for_task(task_id, interval, period)

        if task['status'] == 'failed':
            self.log_message(
                f"HA creation task failed with the following reason: {task['failure_reason']}", 'error'
            )
            raise F5ModuleError(f"HA creation task failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("HA creation task completed successfully")
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
        uri = f"/device/v1/ha-creation-tasks/{task_id}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return response['contents']


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            ha_name=dict(required=True),
            ha_ip=dict(required=True),
            active_node_ip=dict(required=True),
            standby_node_ip=dict(required=True),
            active_node_control_plane_ip=dict(required=True),
            standby_node_control_plane_ip=dict(required=True),
            control_plane_vlan=dict(required=True),
            control_plane_vlan_tag=dict(type='int'),
            active_node_data_plane_ip=dict(required=True),
            standby_node_data_plane_ip=dict(required=True),
            data_plane_vlan=dict(required=True),
            data_plane_vlan_tag=dict(type='int'),
            external=dict(
                type='dict',
                options=dict(
                    network_name=dict(),
                    vlan=dict(),
                    tag=dict(type='int'),
                    floating_ip=dict(),
                    active_ip=dict(),
                    standby_ip=dict(),
                ),
                required_together=[
                    ['network_name', 'vlan', 'floating_ip', 'active_ip', 'standby_ip']
                ],
                required_by={
                    'tag': 'vlan'
                }
            ),
            internal=dict(
                type='dict',
                options=dict(
                    network_name=dict(),
                    vlan=dict(),
                    tag=dict(type='int'),
                    floating_ip=dict(),
                    active_ip=dict(),
                    standby_ip=dict(),
                ),
                required_together=[
                    ['network_name', 'vlan', 'floating_ip', 'active_ip', 'standby_ip']
                ],
                required_by={
                    'tag': 'vlan'
                }
            ),
            timeout=dict(
                type='int',
                default=300
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
