#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_next_deploy_vmware
short_description: Module to manage deployments of BIG-IP NEXT instances on VMWARE
description:
  - Module to manage deployments of BIG-IP NEXT instances on VMWARE using
    vSphere provider.
version_added: 1.0.0
options:
  provider:
    description:
      - Settings related to vSphere environment.
    type: dict
    suboptions:
      provider_name:
        description:
          - Name of the configured vSphere provider as it exists on CM.
        type: str
        required: true
      cluster:
        description:
          - The name of the vSphere cluster in the C(datacenter) where to deploy
            the instance.
        type: str
        required: true
      datacenter:
        description:
          - The name of the vSphere datacenter to use.
        type: str
        required: true
      resource_pool:
        description:
          - The name of the vSphere resource_pool to use.
        type: str
        required: true
      datastore:
        description:
          - The name of the vSphere datastore to use.
        type: str
        required: true
      content_library:
        description:
          - The name of the vSphere content library to use.
        type: str
        required: true
      template:
        description:
          - The name of the vSphere content library to use.
        type: str
        required: true
  instance:
    description:
      - Settings related to NEXT instance provisioning.
    type: dict
    suboptions:
      instance_hostname:
        description:
          - Hostname for the deployed BIG-IP NEXT instance.
        type: str
        required: true
      memory:
        description:
          - The amount of memory in kilobytes to allocate for deployed instance.
        type: int
        default: 16384
      cpus:
        description:
          - The number of cpus to allocate for deployed instance.
        type: int
        default: 8
      dns:
        description:
          - The addresses of DNS servers to configure in the deployed instance.
        type: list
        elements: str
      ntp:
        description:
          - The addresses of NTP servers to configure in the deployed instance.
        type: list
        elements: str
      mgmt_address:
        description:
          - The desired management IP address for the BIG-IP NEXT instance.
          - The IP address must be provided in CIDR format e.g. 192.168.1.1/24.
        type: str
        required: true
      mgmt_gateway:
        description:
          - The gateway to set so that C(mgmt_address) can be reached.
          - The address must be in the provided C(mgmt_address) CIDR range,
            otherwise deployment will fail.
        type: str
        required: true
      mgmt_user:
        description:
          - The desired username used by CM to manage BIG-IP NEXT instance.
        type: str
        required: true
      mgmt_password:
        description:
          - The desired password used by CM to manage BIG-IP NEXT instance.
        type: str
        required: true
      mgmt_network_name:
        description:
          - The name of the network in vSphere used to communicate with created
            BIG-IP NEXT instances.
        type: str
        required: true
      external_network_name:
        description:
          - The name of the network in vSphere that will be used as an external
            network in deployed BIG-IP NEXT instance.
        type: str
        required: true
      internal_network_name:
        description:
          - The name of the network in vSphere that will be used as an external
            network in deployed BIG-IP NEXT instance.
        type: str
      ha_dp_network_name:
        description:
          - The name of the network in vSphere that will be used as a dataplane
            network for HA in deployed BIG-IP NEXT instance.
        type: str
      external_vlan_name:
        description:
          - The name of the VLAN to configure for external network in the BIG-IP
            NEXT instance.
        type: str
      internal_vlan_name:
        description:
          - The name of the VLAN to configure for internal network in the BIG-IP
            NEXT instance.
          - When provided this parameter requires C(internal_network_name) to be
            defined.
        type: str
      external_vlan_tag:
        description:
          - The vlan tag for external vlan.
          - When provided this parameter requires C(external_vlan_name) to be
            defined.
        type: int
      internal_vlan_tag:
        description:
          - The vlan tag for internal vlan.
          - When provided this parameter requires C(internal_vlan_name) to be
            defined.
        type: int
      external_ip_address:
        description:
          - The non-floating IP address for external network in the BIG-IP NEXT
            instance.
          - When provided this parameter requires C(external_vlan_name) to be
            defined.
          - The IP address must be provided in CIDR format e.g. 192.168.1.1/24.
        type: str
      internal_ip_address:
        description:
          - The non-floating IP address for internal network in the BIG-IP NEXT
            instance.
          - When provided this parameter requires C(internal_vlan_name) to be
            defined.
          - The IP address must be provided in CIDR format e.g. 192.168.1.1/24.
        type: str
  task_id:
    description:
      - The unique id to identify the deployment task.
      - Parameter required when C(state) is C(present).
    type: str
  wait_for_finish:
    description:
      - Allows the user to specify if the module should wait for task with the
        given C(task_id) to finish.
      - If C(yes) the module will wait for the given C(timeout) period for the
        deployment task to finish running.
      - If C(no) the module will check for the status of the deployment task and
        return the result.
      - If the task has finished running successfully, the module will indicate
        a change and return a message.
      - If the task has failed the module will  throw an exception and return
        the failure reason.
    type: bool
    default: true
  timeout:
    description:
      - The amount of time to wait for the deployment task to finish, in seconds.
      - The accepted value range is between C(10) and C(3600) seconds.
    type: int
    default: 900
  state:
    description:
      - When C(state) is C(deploy), ensures the deployment task is started.
      - When C(state) is C(present), checks for status of existing deployment
        task.
    type: str
    choices:
      - present
      - deploy
    default: deploy
notes:
  - Module runs asynchronously, this means it is not IDEMPOTENT until the
    desired BIG-IP NEXT instance has been provisioned and registered in CM.
    Repeating the same deployment task twice will produce unexpected results.
  - To check the results of deploy task use the provided C(task_id) and C(state)
    set to C(present).
author:
  - Ravinder Reddy (@RavinderReddyF5)
  - Wojciech Wypior (@wojtek0806)

'''

EXAMPLES = r'''
- name: Deploy BIG-IP NEXT instance on vSphere
  cm_next_deploy_vmware:
    state: "deploy"
    provider:
      provider_name: "vCenterDemo"
      cluster: "DemoCluster"
      datacenter: "DemoDatacenter"
      resource_pool: "Demos"
      datastore: "DemoSAN"
      content_library: "EXT-DEM"
      template: "BIG-IP-Next-20.0.1-2.139.10-0.0.136-VM-template"
    instance:
      instance_hostname: "demoVM01.lab.local"
      dns:
        - "8.8.8.8"
        - "8.8.4.4"
      ntp:
        - "time.google.com"
        - "time1.google.com"
      mgmt_address: "172.16.1.1/24"
      mgmt_gateway: "172.16.1.254"
      mgmt_user: "admin"
      mgmt_password: "s3KrI!T"
      mgmt_network_name: "VM_DEMO_MGMT"
      external_network_name: "DemoNet123"
      internal_network_name: "DemoNet456"
      external_vlan_name: "ExtDemoVlan"
      external_vlan_tag: 123
      external_ip_address: "192.168.1.1/24"
      internal_vlan_name: "IntDemoVlan"
      internal_vlan_tag: 456
      internal_ip_address: "192.168.2.1/24"
  register: task

- name: Check the deployment status
  cm_next_deploy_vmware:
    state: "present"
    task_id: "{{ task.task_id }}"
    timeout: 1000
'''

RETURN = r'''
task_id:
  description: The unique task id returned when deployment task has started.
  returned: changed
  type: str
  sample: "6a0c8602-a115-4d16-b684-103318e703fc"
message:
  description: Informative message about the deployment task.
  returned: changed
  type: str
  sample: "Deployment has started"
'''
import os
import time

from ipaddress import ip_interface

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, process_json
)
from ..module_utils.ipaddress import is_valid_ip_interface, is_valid_cidr
from ..module_utils.templates.deploy import vsphere

from ..module_utils.logging import sanitize_sensitive_data


class Parameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'provider_name',
        'cluster',
        'datacenter',
        'resource_pool',
        'datastore',
        'content_lib',
        'template',
        'instance_hostname',
        'memory',
        'cpus',
        'dns',
        'ntp',
        'mgmt_address',
        'mgmt_net_width',
        'mgmt_gw',
        'mgmt_user',
        'mgmt_password',
        'mgmt_net_name',
        'ext_net_name',
        'int_net_name',
        'ext_vlan_name',
        'int_vlan_name',
        'ext_vlan_tag',
        'int_vlan_tag',
        'ext_ip_addr',
        'int_ip_addr',
        'ha_dp_network_name',
        'task_id',
        'message'
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @staticmethod
    def _validate_intf_cidr(addr):
        if addr:
            if not is_valid_ip_interface(addr):
                raise F5ModuleError(f"A submitted IP address: {addr} is not a valid IP interface address.")
            if not is_valid_cidr(addr):
                raise F5ModuleError(f"A submitted IP address: {addr} is not provided in a CIDR format.")

    @property
    def provider_name(self):
        return self._values['provider'].get('provider_name')

    @property
    def cluster(self):
        return self._values['provider'].get('cluster')

    @property
    def datacenter(self):
        return self._values['provider'].get('datacenter')

    @property
    def resource_pool(self):
        return self._values['provider'].get('resource_pool')

    @property
    def datastore(self):
        return self._values['provider'].get('datastore')

    @property
    def content_lib(self):
        return self._values['provider'].get('content_library')

    @property
    def template(self):
        return self._values['provider'].get('template')

    @property
    def instance_hostname(self):
        return self._values['instance'].get('instance_hostname')

    @property
    def memory(self):
        return self._values['instance'].get('memory')

    @property
    def cpus(self):
        return self._values['instance'].get('cpus')

    @property
    def dns(self):
        return self._values['instance'].get('dns')

    @property
    def ntp(self):
        return self._values['instance'].get('ntp')

    @property
    def mgmt_address(self):
        ip = self.mgmt_raw_address
        if ip:
            return str(ip_interface(ip).ip)

    @property
    def mgmt_raw_address(self):
        ip = self._values['instance'].get('mgmt_address')
        self._validate_intf_cidr(ip)
        return ip

    @property
    def mgmt_net_width(self):
        ip = self.mgmt_raw_address
        if ip:
            return ip_interface(ip).network.prefixlen

    @property
    def mgmt_gw(self):
        return self._values['instance'].get('mgmt_gateway')

    @property
    def mgmt_user(self):
        return self._values['instance'].get('mgmt_user')

    @property
    def mgmt_password(self):
        return self._values['instance'].get('mgmt_password')

    @property
    def mgmt_net_name(self):
        return self._values['instance'].get('mgmt_network_name')

    @property
    def ext_net_name(self):
        return self._values['instance'].get('external_network_name')

    @property
    def int_net_name(self):
        return self._values['instance'].get('internal_network_name')

    @property
    def ext_vlan_name(self):
        return self._values['instance'].get('external_vlan_name')

    @property
    def int_vlan_name(self):
        return self._values['instance'].get('internal_vlan_name')

    @property
    def ext_vlan_tag(self):
        return self._values['instance'].get('external_vlan_tag')

    @property
    def int_vlan_tag(self):
        return self._values['instance'].get('internal_vlan_tag')

    @property
    def ext_ip_addr(self):
        ip = self._values['instance'].get('external_ip_address')
        self._validate_intf_cidr(ip)
        return ip

    @property
    def int_ip_addr(self):
        ip = self._values['instance'].get('internal_ip_address')
        self._validate_intf_cidr(ip)
        return ip

    @property
    def ha_dp_network_name(self):
        return self._values['instance'].get('ha_dp_network_name')

    @property
    def timeout(self):
        divisor = 10
        timeout = self._values['timeout']
        if timeout < 10 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 10 and 3600 seconds."
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
        'task_id',
        'message'
    ]


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.provider_uuid = None

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

        if state == "deploy":
            changed = self.deploy()
        elif state == "present":
            changed = self.present()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def deploy(self):
        if self.exists():
            return False
        else:
            return self.create()

    def present(self):
        self.task_exists()
        return self.task_finished()

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.deploy_on_device()
        return True

    def exists(self):
        if not self.provider_exists():
            self.log_message(f"The specified provider: {self.want.provider_name} does not exist.", 'error')
            raise F5ModuleError(f"The specified provider: {self.want.provider_name} does not exist.")
        return self.instance_exists()

    def task_exists(self):
        uri = f"/device/v1/instances/tasks/{self.want.task_id}"

        response = self.client.get(uri)

        if response['code'] == 404:
            self.log_message(f"The specified deployment task:{self.want.task_id} was not found.", 'error')
            raise F5ModuleError(f"The specified deployment task:{self.want.task_id} was not found.")

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("The specified deployment task found")
        return True

    def provider_exists(self):
        uri = f"/device/v1/providers/vsphere?filter=name+eq+'{self.want.provider_name}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if not response['contents'].get('_embedded'):
            self.log_message("Provider not found")
            return False

        if len(response['contents']['_embedded']['providers']) > 1:
            self.log_message(f"Query returned more than 1 provider with the name: {self.want.name}", 'error')
            raise F5ModuleError(
                f"Query returned more than 1 provider with the name: {self.want.provider_name}"
            )

        self.provider_uuid = response['contents']['_embedded']['providers'][0]['id']
        self.log_message(f"Found provider: {self.provider_uuid}")
        return True

    def instance_exists(self):
        uri = f"/device/v1/inventory?filter=address+eq+'{self.want.mgmt_address}'"

        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'].get('count', 0) == 0:
            self.log_message(f"The specified instance not found: {self.want.mgmt_address}")
            return False

        if response['contents']['count'] == 1:
            self.log_message(f"Specified BIG-IP Next instance: {self.want.mgmt_address} found")
            return True
        else:
            self.log_message(f"Query returned more than 1 instance with the specified ip address: "
                             f"{self.want.device_ip}", 'error'
                             )
            raise F5ModuleError(
                f"Query returned more than 1 instance with the specified ip address: "
                f"{self.want.device_ip} "
            )

    def deploy_on_device(self):
        params = self.changes.to_return()
        params['provider_id'] = self.provider_uuid
        self.log_message(
            f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")

        output = process_json(params, vsphere)

        self.log_message(
            f"Generated JSON: {sanitize_sensitive_data(output, self.client.to_obfuscate())}")

        uri = "/device/v1/instances"
        response = self.client.post(uri, output)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        task_id = os.path.basename(response['contents']['path'])
        self.log_message(f"'BIG-IP Next deployment task started: {task_id}")
        self.changes.update({'message': 'BIG-IP Next deployment started.'})
        self.changes.update({'task_id': f"{task_id}"})
        return True

    def task_finished(self):
        interval, period = self.want.timeout

        if not self.want.wait_for_finish:
            task = self._check_task_on_device(self.want.task_id)
        else:
            task = self.wait_for_task(self.want.task_id, interval, period)

        if task['status'] == 'running':
            self.log_message("Deployment task still running")
            self.changes.update({'message': 'BIG-IP Next deployment task still running.'})
            return False

        if task['status'] == 'failed':
            self.log_message(
                f"Instance deployment failed with the following reason: {task['failure_reason']}", 'error'
            )
            raise F5ModuleError(f"Instance deployment failed with the following reason: {task['failure_reason']}")

        if task['status'] == 'completed':
            self.log_message("BIG-IP Next deployment task completed successfully")
            self.changes.update({'message': 'BIG-IP Next deployment successful.'})
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
        uri = f"/device/v1/instances/tasks/{task_id}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            task_id=dict(),
            wait_for_finish=dict(
                type='bool',
                default='yes'
            ),
            provider=dict(
                type='dict',
                options=dict(
                    provider_name=dict(
                        required=True,
                    ),
                    cluster=dict(
                        required=True,
                    ),
                    datacenter=dict(
                        required=True,
                    ),
                    resource_pool=dict(
                        required=True,
                    ),
                    datastore=dict(
                        required=True,
                    ),
                    content_library=dict(
                        required=True,
                    ),
                    template=dict(
                        required=True,
                    ),
                ),
            ),
            instance=dict(
                type='dict',
                options=dict(
                    instance_hostname=dict(
                        required=True
                    ),
                    memory=dict(
                        type='int',
                        default=16384
                    ),
                    cpus=dict(
                        type='int',
                        default=8
                    ),
                    dns=dict(
                        type='list',
                        elements='str'
                    ),
                    ntp=dict(
                        type='list',
                        elements='str'
                    ),
                    mgmt_address=dict(
                        required=True
                    ),
                    mgmt_gateway=dict(
                        required=True
                    ),
                    mgmt_user=dict(
                        required=True
                    ),
                    mgmt_password=dict(
                        required=True,
                        no_log=True
                    ),
                    mgmt_network_name=dict(
                        required=True
                    ),
                    external_network_name=dict(
                        required=True
                    ),
                    ha_dp_network_name=dict(),
                    internal_network_name=dict(),
                    external_vlan_name=dict(),
                    internal_vlan_name=dict(),
                    external_vlan_tag=dict(type='int'),
                    internal_vlan_tag=dict(type='int'),
                    external_ip_address=dict(),
                    internal_ip_address=dict(),
                ),
                required_by={
                    'external_vlan_name': 'external_network_name',
                    'internal_vlan_name': 'internal_network_name',
                    'external_vlan_tag': 'external_vlan_name',
                    'internal_vlan_tag': 'internal_vlan_name',
                    'internal_ip_address': 'internal_vlan_name',
                    'external_ip_address': 'external_vlan_name',
                }
            ),
            state=dict(
                default='deploy',
                choices=['deploy', 'present']
            ),
            timeout=dict(
                type='int',
                default=900
            ),
        )
        self.mutually_exclusive = [
            ['provider', 'task_id'],
            ['instance', 'task_id'],
        ]
        self.required_if = [
            ['state', 'present', ['task_id']],
            ['state', 'deploy', ['provider', 'instance']]
        ]
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)


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
