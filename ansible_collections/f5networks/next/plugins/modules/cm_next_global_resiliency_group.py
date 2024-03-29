#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_next_global_resiliency_group
short_description: Manages Global Resiliency Group on the Central Manager.
description:
  - Manages Global Resiliency Group on the Central Manager.
version_added: 1.0.0
options:
  name:
    description:
      - Specifies the name of the global resiliency group.
    type: str
    required: True
  dns_listener_name:
    description:
      - Specifies the name of the DNS listener.
    type: str
  dns_listener_port:
    description:
      - Specifies the port number of the DNS listener.
    type: int
  protocols:
    description:
      - Specifies the protocols to be used.
    type: list
    elements: str
    choices:
      - tcp
      - udp
  instances:
    description:
      - Specifies the BIG-IP Next instances of the global resiliency group.
    type: list
    elements: raw
    suboptions:
      address:
        description:
          - Specifies the IP address of the BIG-IP Next instance.
        type: str
      hostname:
        description:
          - Specifies the hostname of the BIG-IP Next instance.
        type: str
      dns_listener_address:
        description:
          - Specifies the DNS listener address of the BIG-IP Next instance.
        type: str
      group_sync_address:
        description:
          - Specifies the group sync address of the BIG-IP Next instance.
        type: str
  timeout:
    description:
      - Specifies the amount of time to wait for the global resiliency
        group to be created or updated.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(present), ensures the global resiliency group is
        created/renewed on the Central Manager.
      - When C(absent), ensures the global resiliency group is
        removed from the the Central Manager.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Rohit Upadhyay (@rupadhyay)
'''

EXAMPLES = r'''
- name: Create a Global Resiliency Group on CM
  cm_next_global_resiliency_group:
    name: "testgroup"
    dns_listener_name: "testdnslistener"
    dns_listener_port: 7373
    protocols:
      - "udp"
      - "tcp"
    instances:
      - address: "10.28.18.22"
        hostname: "big-ip-next"
        dns_listener_address: "10.34.21.56"
        group_sync_address: "10.34.21.56/24"

      - address: "10.28.15.19"
        hostname: "example2.com"
        dns_listener_address: "18.217.24.145"
        group_sync_address: "18.217.24.145/24"
'''

RETURN = r'''
name:
  description: The name of the global resiliency group.
  returned: changed
  type: str
  sample: testGRG
dns_listener_name:
  description: The name of the DNS listener.
  returned: changed
  type: str
  sample: testDNSListener
dns_listener_port:
  description: The port number of the DNS listener.
  returned: changed
  type: int
  sample: 7373
protocols:
  description: The protocols to be used.
  returned: changed
  type: list
  elements: str
  sample:
    - "udp"
    - "tcp"
'''
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)


class Parameters(AnsibleF5Parameters):
    api_map = {

    }

    api_attributes = [
        'dns_listener_port',
        'protocols',
        'instances',
    ]

    returnables = [
        'dns_listener_port',
        'protocols',
        'instances',
    ]

    updatables = [
        'instances',
    ]


class ApiParameters(Parameters):
    pass


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


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):  # pragma: no cover
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def instances(self):
        have = self.have.instances
        want = self.want.instances
        have = sorted(have, key=lambda x: x['address'])
        want = sorted(want, key=lambda x: x['address'])

        keys = ['address', 'dns_listener_address', 'group_sync_address']

        if len(have) != len(want):
            return want

        for i in range(len(have)):
            for key in keys:
                if have[i][key] != want[i][key]:
                    return want


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.grc_id = None

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
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

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        self.remove_from_device()
        time.sleep(12)
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "/v1/spaces/default/gslb/gr-groups"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['count'] == 0:
            return False

        groups = response['contents']['_embedded']['groups']
        for group in groups:
            if group['name'] == self.want.name:
                self.grc_id = group['id']
                return True

        return False

    def add_missing_values(self, params):
        if 'protocols' not in params:
            params['protocols'] = self.have.protocols
        if 'dns_listener_port' not in params:
            params['dns_listener_port'] = self.have.dns_listener_port

        return params

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['dns_listener_name'] = self.want.dns_listener_name

        uri = "/v1/spaces/default/gslb/gr-groups"
        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        interval, period = self.want.timeout
        self.grc_id = response['contents']['path'].rsplit('/', 1)[-1]
        created = self.check_status("create", interval, period)

        if not created:
            raise F5ModuleError("The create process is not complete yet")

        return True

    def update_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['dns_listener_name'] = self.want.dns_listener_name
        params = self.add_missing_values(params)

        uri = f"/v1/spaces/default/gslb/gr-groups/{self.grc_id}"
        response = self.client.put(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        interval, period = self.want.timeout
        updated = self.check_status("update", interval, period)

        if not updated:
            raise F5ModuleError("The update process is not complete yet")

        return True

    def remove_from_device(self):
        uri = f"/v1/spaces/default/gslb/gr-groups/{self.grc_id}"
        self.log_message(f'deleting: {self.want.name}')
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            if response['contents']['message'] == "Deleting the Global Resiliency Group":
                return True
        raise F5ModuleError(response['contents'])

    def check_status(self, status, interval, period):
        uri = f"/v1/spaces/default/gslb/gr-groups/{self.grc_id}"
        for x in range(0, period):
            response = self.client.get(uri)
            if status == "delete":
                if response['code'] == 404:
                    return True
            if status in ['create', 'update']:
                if response['contents']['status'] == "DEPLOYED":
                    return True
                if response['contents']['status'] == "FAILED":
                    raise F5ModuleError("The resource is in FAILED state")
            time.sleep(interval)

        return False

    def read_current_from_device(self):
        uri = f"/v1/spaces/default/gslb/gr-groups/{self.grc_id}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            dns_listener_name=dict(),
            dns_listener_port=dict(type='int'),
            protocols=dict(
                type='list',
                elements='str',
                choices=['tcp', 'udp']
            ),
            instances=dict(
                type='list',
                elements='raw',
                options=dict(
                    address=dict(),
                    hostname=dict(),
                    dns_listener_address=dict(),
                    group_sync_address=dict(),
                )
            ),
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
