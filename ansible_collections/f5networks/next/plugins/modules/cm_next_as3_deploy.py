#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: cm_next_as3_deploy
short_description: Manages Deploying an AS3 declaration to a specified instance managed by BIG-IP Next Central Manager.
description:
  - Manages Deploying an AS3 declaration to a specified instance managed by BIG-IP Next Central Manager.
version_added: 1.0.0
options:
  content:
    description:
      - The declaration to be configured on the system.
      - This parameter is most often used with the C(file) or C(template) lookup plugins.
        Refer to the examples section for correct usage.
      - For anything advanced or with formatting, consider using the C(template) lookup.
      - Additionally, this can be used for specifying application service configurations
        directly in YAML. However that is not an encouraged practice and, if used at all,
        should only be used for the absolute smallest of configurations to prevent your
        Playbooks from becoming too large.
      - If your C(content) includes encrypted values (such as ciphertexts, passphrases, etc),
        the returned C(changed) value will always be true.
      - If you are using the C(to_nice_json) filter, it causes this module to fail because
        the purpose of that filter is to format the JSON to be human-readable and this process
        includes inserting extra characters that break JSON validators.
    type: raw
    required: True
  target_ip:
    description:
      - The IP address of the BIG-IP Next instance on which to manage the AS3 declaration.
    type: str
    required: True
  timeout:
    description:
      - The amount of time to wait for the AS3 interface to complete the deletion task, in seconds.
      - The accepted value range is between C(10) and C(1800) seconds.
    type: int
    default: 300
  state:
    description:
      - When C(state) is C(present), ensures the declaration is exists.
      - When C(state) is C(absent), ensures the declaration is removed.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Ravinder Reddy (@RavinderReddyF5)
'''

EXAMPLES = r'''
- name: Declaration with 2 Tenants - AS3
  cm_next_as3_deploy:
    content: "{{ lookup('file', 'two_tenants.json') }}"
    target_ip: "1.2.3.4"

- name: Remove one tenant - AS3
  cm_next_as3_deploy:
    content: "{{ lookup('file', 'two_tenants.json') }}"
    target_ip: "1.2.3.4"
    state: absent
'''

RETURN = r'''
content:
  description: The declaration sent to the system.
  returned: changed
  type: dict
  sample: hash/dictionary of values
target_ip:
  description: The IP address of the BIG-IP Next instance on which to deploy the AS3 declaration.
  returned: changed
  type: str
  sample: 1.2.3.4
'''

import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.six import string_types

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters,
)
from ..module_utils.logging import sanitize_sensitive_data

try:
    import json
except ImportError:  # pragma: no cover
    import simplejson as json


class Parameters(AnsibleF5Parameters):
    api_map = {}
    api_attributes = [
        'content',
        'target_ip',
    ]
    returnables = [
        'content',
        'target_ip',
    ]
    updatables = returnables


class ApiParameters(Parameters):
    @property
    def content(self):
        return self._values['contents'].get('app_data')

    @property
    def target_ip(self):
        return self._values.get('target_ip')


class ModuleParameters(Parameters):
    @property
    def content(self):
        if self._values['content'] is None:
            return None
        if isinstance(self._values['content'], string_types):
            return json.loads(self._values['content'] or 'null')
        else:
            return self._values['content']

    @property
    def target_ip(self):
        if self._values.get('target_ip'):
            return self._values.get('target_ip')

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

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:  # pragma: no cover
            return attr1


class ModuleManager(object):

    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.app_name = None
        self.draft_id = None
        self.deploy_id = None
        self.scope = '/api/v1/spaces/default/appsvcs'

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
                    changed.update(change)  # pragma: no cover
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

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
        return self.create()

    def update(self):
        self.have = self.get_deployed_appsvc()
        if not self.should_update():
            self.log_message(f"No new or changed attribute. Aborting update for certificate {self.want.name}.")
            return False
        if self.module.check_mode:  # pragma: no cover
            return True
        self.update_as3_deployment()
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        return self.create_deploy_device()
        # return result

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove(self):
        if self.module.check_mode:  # pragma: no cover
            return True
        result = self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return result

    def exists(self):
        declaration = {}
        if self.want.content is None:
            raise F5ModuleError(
                "Empty content cannot be specified when 'state' is 'present'."
            )
        try:
            declaration.update(self.want.content)
        except ValueError:
            raise F5ModuleError(
                "The provided 'content' could not be converted into valid json. If you "
                "are using the 'to_nice_json' filter, please remove it."
            )

        self.app_name = self.filter_app(self.want.content)
        self.log_message(f"[exists] app name: {self.app_name}")

        uri = (f"/applications?select=health,id,instances,name,gslb_enabled,fqdn,security_policies,type,tenant_name,"
               f"modified,successful_instances,deployments_count&filter=name+eq+'{self.app_name}'")
        self.log_message(f"[exists] uri: {uri}")
        response = self.client.get(uri, scope=self.scope)
        self.log_message(f"[exists] response code: {response['code']}")
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        self.log_message(f"[exists] contents: {response['contents']}")
        if response['contents']['count'] == 0:
            return False
        # if '_embedded' not in response['contents']:
        #     return False
        results = response['contents']['_embedded']['applications']
        for key, val in results[0].items():
            if key == "id":
                self.draft_id = val
            if key == "successful_instances" and val == 0:
                return False
            if key == "instances":
                for msg in val:
                    if msg['address'] == self.want.target_ip:
                        try:
                            self.deploy_id = self.get_deployment_id()
                        except KeyError:
                            return False
                return all(msg.get('address', None) == self.want.target_ip for msg in val)

    def create_deploy_device(self):
        # create draft application on CM
        if self.draft_id is None:
            uri = "/documents"
            self.log_message(f"[create_deploy_device]: uri: {uri}")
            response = self.client.post(uri, self.want.content, scope=self.scope)
            self.log_message(f"[create_deploy_device]: resp: {response}")
            if response['code'] not in [200, 201, 202, 204, 207]:
                raise F5ModuleError(response['contents'])
            self.draft_id = response['contents']['id']

        # deploy application onto specified target_ip
        uri = f"/documents/{self.draft_id}/deployments"
        body = {"target": self.want.target_ip}
        response = self.client.post(uri, body, scope=self.scope)
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        results = response['contents']
        self.log_message(f"[create_deploy_device] resp: {results}")
        self.deploy_id = results['id']
        self.have = self.get_deployed_appsvc()
        self.log_message(f"[create_deploy_device] results: {self.have.content}")
        return True

    def get_deployment_id(self):
        uri = f"mgmt/shared/appsvcs/declare/{self.draft_id}"
        # uri = f"/declare/{self.draft_id}"
        self.log_message(f" uri: {uri}")
        # uri = f"/documents/{self.draft_id}/deployments"
        response = self.client.get(uri, scope="/")
        self.log_message(f" resp code: {response.get('code')}")
        self.log_message(f" resp contents: {response.get('contents')}")
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return response['contents']['deployments'][0]['id']

    # def wait_for_task(self, path, delay, period):
    #     for x in range(0, period):
    #         task = self._check_task_on_device(path)
    #         if task['status'] == 'completed' and task['state'] == 'delDone':
    #             return task
    #         if bool(task.get('failure_reason')):
    #             raise F5ModuleError(task['failure_reason'])
    #         time.sleep(delay)
    #     raise F5ModuleError(
    #         "Module timeout reached, state change is unknown, "
    #         "please increase the timeout parameter for long lived actions."
    #     )

    def get_deployed_appsvc(self):
        uri = f"/documents/{self.draft_id}/deployments/{self.deploy_id}"
        # uri = f"/documents/{self.draft_id}/deployments"
        self.log_message(f"[get_deployed_appsvc] uri: {uri}")

        delay, period = self.want.timeout
        for x in range(0, period):
            response = self.client.get(uri, scope=self.scope)
            self.log_message(f"[get_deployed_appsvc] resp: {response.get('contents')}")
            if response['code'] not in [200, 201, 202]:
                raise F5ModuleError(response['contents'])
            results = response['contents']
            if results['records'][0]['status'] in ['completed', 'failed']:
                break
            time.sleep(delay)
        response = self.client.get(uri, scope=self.scope)
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        results = response['contents']
        if results['records'][0]['status'] not in ['completed', 'failed']:
            raise F5ModuleError("Deployment task did not complete in the specified timeout period")
        if results['records'][0]['status'] == 'failed':
            raise F5ModuleError(results['records'][0]['failure_reason'])
        results = dict()
        results.update(dict(target_ip=self.want.target_ip))
        results.update(dict(contents=response['contents']))
        return ApiParameters(params=results)

    def update_as3_deployment(self):
        params = self.changes.api_params()
        self.log_message(f"Updating Draft {self.draft_id}")
        # uri = f"/documents/{self.draft_id}/deployments/{self.deploy_id}"
        uri = f"/documents/{self.draft_id}"
        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")
        body = self.want.content
        if 'content' not in params:
            body = self.want.content
        response = self.client.put(uri, body, scope=self.scope)
        self.log_message(f"Updating Response {response}")
        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])
        return True

    def remove_from_device(self):
        delay, period = self.want.timeout
        # uri = f"/documents/{self.draft_id}/deployments/{self.deploy_id}"
        uri = f"/documents/{self.draft_id}"
        self.log_message(f"[remove_from_device] url {uri}")
        response = self.client.delete(uri, scope=self.scope)
        if response['code'] not in [200, 201, 202, 204, 207]:
            raise F5ModuleError(response['contents'])
        self.log_message(f"[remove_from_device]resp: {response.get('contents')}")
        return True

    def filter_app(self, content):
        for key, value in content.items():
            if isinstance(value, dict):
                self.app_name = key
                self.filter_app(value)
            else:
                if key == 'class' and value == 'Application':
                    break
        return self.app_name


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            content=dict(type='raw', required=True),
            target_ip=dict(type='str', required=True),
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
        self.required_if = [
            ['state', 'present', ['content', 'target_ip']]
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
        mm.log_message(f"content: {mm.want.content}")
        mm.log_message(f"app_name:{mm.want.app_name}")
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':  # pragma: no cover
    main()
