#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_next_license
short_description: Manage license activation and deactivation of BIG-IP Next instances.
description:
  - Manage license activation and deactivation of BIG-IP Next instances through Central Manager API.
version_added: 1.3.0
options:
  next_ips:
    description:
      - The IP addresses of the BIG-IP Next instances that are to be activated or deactivated.
    type: list
    elements: str
    required: True
  jwt:
    description:
      - The json web token to be used for license activation.
      - Required when C(jwt_type) is set to C(new).
    type: str
  jwt_name:
    description:
      - The name of the json web token to be used for license activation.
      - Required when C(state) is set to C(activate).
    type: str
  jwt_type:
    description:
      - This tells whether to create and use a new jwt or use an existing one.
    type: str
    choices:
      - existing
      - new
  timeout:
    description:
      - The time in seconds to wait for the license activation or deactivation to complete.
      - The accepted value range is between C(150) and C(3600) seconds.
    type: int
    default: 300
  state:
    description:
      - The state of the license to be set.
    type: str
    choices:
      - activate
      - deactivate
    default: activate
author:
  - Author Name (@rupadhyay)
'''

EXAMPLES = r'''
- name: license two BIG-IP Next instances through CM
  cm_next_license:
    jwt_name: "test_token"
    jwt_type: "new"
    jwt: "{{ lookup('file', 'jwt.txt') }}"
    next_ips:
      - "1.2.3.4"
      - "4.3.2.1"
    state: activate
'''

RETURN = r'''
next_ips:
  description: The list of BIG-IP Next instances.
  returned: changed
  type: list
  sample: ["1.2.3.4", "4.3.2.1"]
jwt_type:
  description: The type of json web token, whether it is existing or new.
  returned: changed
  type: str
  sample: "new"
jwt_name:
  description: The name that identifies the json web token on Central Manager.
  returned: changed
  type: str
  sample: "test_token"
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

    ]

    returnables = [

    ]

    updatables = [

    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def next_ips(self):
        return self._values['next_ips']

    @property
    def timeout(self):
        divisor = 100
        timeout = self._values['timeout']
        if timeout < 150 or timeout > 3600:
            raise F5ModuleError(
                "Timeout value must be between 150 and 3600 seconds."
            )

        delay = timeout / divisor

        return delay, divisor


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
        self.device_ids = None
        self.license_status = None
        self.jwt_id = None

    def _set_changed_options(self):  # pragma: no cover
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):  # pragma: no cover
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

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        if state == "activate":
            changed = self.present()
        elif state == "deactivate":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def present(self):
        if not self.exists():
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):  # pragma: no cover
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):  # pragma: no cover
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
        if self.exists():
            raise F5ModuleError("Failed to deactivate the BIG-IP Next instance(s).")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def get_device_id(self):
        uri = "/v1/spaces/default/instances"
        response = self.client.get(uri)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        next_devices = response['contents']['_embedded']['devices']

        ip_to_id = dict()

        for device in next_devices:
            if device['address'] in self.want.next_ips:
                ip_to_id[device['address']] = device['id']

        return ip_to_id

    def get_license_status(self):
        if self.device_ids is None:
            raise F5ModuleError(
                "cannot get license status without device ID."
            )

        params = {'digitalAssetIds': list(self.device_ids.values())}
        uri = "/v1/spaces/default/instances/license/license-info"
        response = self.client.post(uri, body=params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        resp = response['contents']

        id_to_status = dict()
        for id in self.device_ids.values():
            id_to_status[id] = resp[id]["deviceLicenseStatus"]["licenseStatus"]

        return id_to_status

    def get_jwt_id(self):
        if self.want.jwt_type in ["new", "New"]:
            self.jwt_id = self.create_jwt()
            return

        uri = "/v1/spaces/default/license/tokens"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents'] is None:
            raise F5ModuleError(
                "No tokens are present on the CM"
            )

        for token in response['contents']:
            if token['nickName'] == self.want.jwt_name:
                self.jwt_id = token['id']
                return

        raise F5ModuleError(
            f"jwt, {self.want.jwt_name} does not exist on the CM."
        )

    def create_jwt(self):
        uri = "/v1/spaces/default/license/tokens"
        params = {
            "nickName": self.want.jwt_name,
            "jwt": self.want.jwt,
        }

        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if "NewToken" in response["contents"]:
            return response["contents"]["NewToken"]["id"]
        else:
            raise F5ModuleError(
                "could not create a new jwt."
            )

    def exists(self):
        self.device_ids = self.get_device_id()

        for ip in self.want.next_ips:
            if ip not in self.device_ids:
                raise F5ModuleError(
                    f"BIG-IP Next device with IP address, {ip}, was not found on the Central Manager"
                )

        self.license_status = self.get_license_status()

        for v in self.license_status.values():
            if v.lower() in ['inactive', 'not active', 'deactivated']:
                return False

        return True

    def create_on_device(self):
        self.get_jwt_id()
        params = []

        for id, status in self.license_status.items():
            if status.lower() in ['inactive', 'not active', 'deactivated']:
                params.append({"digitalAssetId": id, "jwtId": self.jwt_id})

        uri = "/v1/spaces/default/instances/license/activate"

        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        tasks = []

        for device_id in response['contents']:
            tasks.append(response['contents'][device_id]['taskId'])

        return self.wait_for_task(tasks)

    def wait_for_task(self, tasks):
        params = {"licenseTaskIds": tasks}
        uri = "/v1/spaces/default/license/tasks"

        resp = None
        delay, period = self.want.timeout
        for x in range(0, period):
            resp = self.client.post(uri, params)

            if resp['code'] not in [200, 201, 202]:
                raise F5ModuleError(resp['contents'])

            for device_id, task in resp['contents'].items():
                if task['taskExecutionStatus']['status'] == 'failed':
                    raise F5ModuleError(
                        f"License {self.want.state} task failed for device {device_id}"
                    )
            if all(task['taskExecutionStatus']['status'] == 'completed' for x, task in resp['contents'].items()):
                return True
            else:
                time.sleep(delay)
        return False

    def remove_from_device(self):
        uri = "/v1/spaces/default/instances/license/deactivate"
        params = {
            "digitalAssetIds": list(self.device_ids.values())
        }
        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        tasks = []

        for device_id in response['contents']:
            tasks.append(response['contents'][device_id]['taskId'])

        return self.wait_for_task(tasks)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            jwt_type=dict(
                choices=['existing', 'new']
            ),
            jwt=dict(no_log=True),
            jwt_name=dict(),
            next_ips=dict(
                type='list',
                elements='str',
                required=True,
            ),
            timeout=dict(
                type='int',
                default=300
            ),
            state=dict(
                choices=['activate', 'deactivate'],
                default='activate',
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ["jwt_type", "new", ["jwt", "jwt_name"]]
        ]


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
