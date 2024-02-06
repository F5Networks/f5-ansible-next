#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_ssl_certificate_create
short_description: Manages certificate and/or key on the Central Manager.
description:
  - Manages certificate and/or key on the Central Manager.
version_added: 1.0.0
options:
  name:
    description:
      - Specifies the name of the certificate/key or the certificate, key pair.
    type: str
    required: True
  issuer:
    description:
      - Specifies the issuer of the certificate.
      - When no value is provided during create, the default value is C(Self).
    type: str
    choices:
      - CA
      - Self
  common_name:
    description:
      - Specifies the common name of the certificate.
      - This option is required when creating a certificate.
    type: str
  duration_in_days:
    description:
      - Specifies the duration of the certificate in days.
      - This option is required when creating a certificate.
    type: int
  subject_alternative_name:
    description:
      - Specifies the subject alternative name of the certificate.
    type: str
  key_type:
    description:
      - Specifies the key type of the certificate.
      - When no value is provided during create, the default value is C(RSA).
    type: str
    choices:
      - RSA
      - ECDSA
  key_size:
    description:
      - Specifies the key size of the certificate.
      - This option is only available when the key type is set to C(RSA).
      - When no value is provided during create and the key_type is set to
        C(RSA), the default value is C(2048).
    type: int
  key_curve_name:
    description:
      - Specifies the key curve name of the certificate.
      - This option is only available when the key type is set to C(ECDSA).
      - When no value is provided during create and the key_type is set to C(ECDSA),
        the default value is C(prime256v1).
    type: str
  key_security_type:
    description:
      - Specifies the key security type of the certificate.
      - When no value is provided during create, the default value is C(Password).
    type: str
    choices:
      - Password
      - Normal
  key_passphrase:
    description:
      - Specifies the key passphrase of the certificate.
      - This option is only available when the key security type is set to C(Password).
    type: str
  update_passphrase:
    description:
      - Specifies whether to update the passphrase of the certificate.
      - This option must be provided and set to C(true) when the user wants to update
        the key passphrase.
    type: bool
    default: false
  division:
    description:
      - Specifies the division.
    type: str
  organization:
    description:
      - Specifies the organization.
    type: str
  locality:
    description:
      - Specifies the locality.
    type: str
  province:
    description:
      - Specifies the province.
    type: str
  country:
    description:
      - Specifies the country.
    type: str
  email:
    description:
      - Specifies the email.
    type: str
  state:
    description:
      - When C(present), ensures the key and/or cert is created/renewed on
        the Central Manager.
      - When C(absent), ensures the key and/or cert is removed from the
        the Central Manager.
    type: str
    choices:
      - present
      - absent
    default: present
author:
  - Rohit Upadhyay (@rupadhyay)
'''

EXAMPLES = r'''
'''

RETURN = r'''
name:
  description: The name of the certificate/key pair.
  returned: changed
  type: str
  sample: testcert
common_name:
  description: Specifies the common name of the certificate.
  returned: changed
  type: str
  sample: example.com
issuer:
  description: Specifies the issuer of the certificate/key pair.
  returned: changed
  type: str
  sample: Self
duration_in_days:
  description: Specifies the duration of the certificate in days.
  returned: changed
  type: int
  sample: 365
subject_alternative_name:
  description: Specifies the subject alternative name of the certificate.
  returned: changed
  type: str
  sample: DNS:example.com
key_type:
  description: Specifies the key type of the certificate.
  returned: changed
  type: str
  sample: RSA
key_size:
  description: Specifies the key size of the certificate. Only available when the key type is set to C(RSA).
  returned: changed
  type: int
  sample: 2048
key_curve_name:
  description: Specifies the key curve name of the certificate. Only available when the key type is set to C(ECDSA).
  returned: changed
  type: str
  sample: prime256v1
key_security_type:
  description: Specifies the key security type of the certificate.
  returned: changed
  type: str
  sample: Password
province:
  description: Specifies the province/state.
  returned: changed
  type: str
  sample: Hyderabad
country:
  description: Specifies the country.
  returned: changed
  type: str
  sample: IN
organization:
  description: Specifies the organization.
  returned: changed
  type: str
  sample: FX
division:
  description: Specifies the division.
  returned: changed
  type: str
  sample: Dev
email:
  description: Specifies the email.
  returned: changed
  type: str
  sample: user@fx.com
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)
from ..module_utils.logging import sanitize_sensitive_data


class Parameters(AnsibleF5Parameters):
    api_attributes = [
        'common_name',
        'issuer',
        'duration_in_days',
        'subject_alternative_name',
        'key_type',
        'key_size',
        'key_curve_name',
        'key_security_type',
        'key_passphrase',
        'locality',
        'province',
        'country',
        'organization',
        'division',
        'email',
    ]

    returnables = api_attributes

    updatables = returnables


class ApiParameters(Parameters):
    @property
    def key_security_type(self):
        key = self._values.get('key')
        if key and key.get('passphrase') == 'key_password_hsm_id':
            return 'Password'
        return 'Normal'

    @property
    def province(self):
        return self._values.get('state')


class ModuleParameters(Parameters):
    @property
    def locality(self):
        if self._values.get('locality'):
            return [self._values.get('locality')]

    @property
    def province(self):
        if self._values.get('province'):
            return [self._values.get('province')]

    @property
    def country(self):
        if self._values.get('country'):
            return [self._values.get('country')]

    @property
    def organization(self):
        if self._values.get('organization'):
            return [self._values.get('organization')]

    @property
    def division(self):
        if self._values.get('division'):
            return [self._values.get('division')]

    @property
    def email(self):
        if self._values.get('email'):
            return [self._values.get('email')]

    @property
    def key_passphrase(self):
        if self._values.get('key_passphrase'):
            return self._values.get('key_passphrase')
        if not self._values.get('key_passphrase'):
            if self.key_security_type in ['Password', None]:
                raise F5ModuleError(
                    "key_passphrase is required when key_security_type is set to 'Password'"
                )


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

    @property
    def key_passphrase(self):
        if self.want.key_security_type in ['Password', None]:
            if flatten_boolean(self.want.update_passphrase) == 'yes':
                return self.want.key_passphrase


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = F5Client(module=self.module, client=self.connection)
        self.want = ModuleParameters(params=self.module.params)
        self.changes = UsableChanges()
        self.have = ApiParameters()
        self.cert_id = None

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
                    changed.update(change)  # pragma: no cover
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
            self.log_message(f"Certificate {self.want.name} exists on the device. Starting update process.")
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
            self.log_message(f"No new or changed attribute. Aborting update for certificate {self.want.name}.")
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
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:  # pragma: no cover
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "/v1/spaces/default/certificates"
        response = self.client.get(uri)

        if response['code'] == 404:
            return False

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        if response['contents']['count'] > 0:
            certs = response['contents']['_embedded']['certificates']

            for cert in certs:
                if cert['name'] == self.want.name:
                    self.log_message(f"Certificate {self.want.name} exists on the device.")
                    self.cert_id = cert.get('id')
                    return True

        return False

    def add_create_values(self, params):
        if self.want.issuer is None:
            params['issuer'] = 'Self'
        if self.want.key_type is None:
            params['key_type'] = 'RSA'
        if self.want.key_size is None and params['key_type'] == 'RSA':
            params['key_size'] = 2048
        if self.want.key_curve_name is None and params['key_type'] == 'ECDSA':
            params['key_curve_name'] = 'prime256v1'
        if self.want.key_security_type is None:
            params['key_security_type'] = 'Password'
        if params['key_security_type'] == 'Password':
            params['key_passphrase'] = self.want.key_passphrase
        if self.want.duration_in_days is None:
            raise F5ModuleError(
                "duration_in_days is required when creating a certificate"
            )
        if self.want.common_name is None:
            raise F5ModuleError(
                "common_name is required when creating a certificate"
            )
        return params

    def add_missing_attributes(self, params):
        if self.changes.issuer is None:
            params['issuer'] = self.have.issuer
        if self.changes.common_name is None:
            params['common_name'] = self.have.common_name
        if self.changes.subject_alternative_name is None:
            params['subject_alternative_name'] = self.have.subject_alternative_name
        if self.changes.duration_in_days is None:
            params['duration_in_days'] = self.have.duration_in_days
        if self.changes.key_type is None:
            params['key_type'] = self.have.key_type
        if self.changes.key_size is None and params['key_type'] == 'RSA':
            params['key_size'] = self.have.key_size
        if self.changes.key_curve_name is None and params['key_type'] == 'ECDSA':
            params['key_curve_name'] = self.have.key_curve_name
        if self.changes.key_security_type is None:
            params['key_security_type'] = self.have.key_security_type
        if self.changes.locality is None:
            params['locality'] = self.have.locality
        if self.changes.province is None:
            params['state'] = self.have.province
        if self.changes.country is None:
            params['country'] = self.have.country
        if self.changes.organization is None:
            params['organization'] = self.have.organization
        if self.changes.division is None:
            params['division'] = self.have.division
        if self.changes.email is None:
            params['email'] = self.have.email

        res = {k: v for k, v in params.items() if v is not None}

        return res

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params = self.add_create_values(params)
        if self.want.province:
            params['state'] = self.want.province
        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")
        self.log_message(f"Creating certificate {self.want.name}")

        uri = "/v1/spaces/default/certificates/create"

        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("Certificate created successfuly")
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        params['id'] = self.cert_id
        params = self.add_missing_attributes(params)

        self.log_message(f"Updating certificate {self.want.name}")
        self.log_message(f"Processed parameters: {sanitize_sensitive_data(params, self.client.to_obfuscate())}")
        uri = "/v1/spaces/default/certificates/renew"
        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return True

    def remove_from_device(self):
        uri = f"/v1/spaces/default/certificates/{self.cert_id}"
        self.log_message(f"Deleting certificate {self.want.name}")
        response = self.client.delete(uri)
        if response['code'] in [200, 201, 202]:
            self.log_message("Certificate deleted successfully")
            return True
        raise F5ModuleError(response['contents'])

    def read_current_from_device(self):
        uri = f"/v1/spaces/default/certificates/{self.cert_id}"
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        return ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(
                type='str',
                required=True
            ),
            issuer=dict(
                type='str',
                choices=['CA', 'Self']
            ),
            common_name=dict(
                type='str',
            ),
            duration_in_days=dict(
                type='int',
            ),
            subject_alternative_name=dict(
                type='str'
            ),
            key_type=dict(
                type='str',
                choices=['RSA', 'ECDSA']
            ),
            key_size=dict(
                type='int'
            ),
            key_curve_name=dict(
                type='str'
            ),
            key_security_type=dict(
                type='str',
                choices=['Password', 'Normal']
            ),
            key_passphrase=dict(
                type='str',
                no_log=True,
            ),
            update_passphrase=dict(
                type='bool',
                default=False,
            ),
            division=dict(
                type='str'
            ),
            organization=dict(
                type='str'
            ),
            locality=dict(
                type='str'
            ),
            province=dict(
                type='str'
            ),
            country=dict(
                type='str'
            ),
            email=dict(
                type='str'
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['key_type', 'RSA', ['key_size']],
            ['key_type', 'ECDSA', ['key_curve_name']],
            ['key_security_type', 'Password', ['key_passphrase']],
        ]
        self.mutually_exclusive = [
            ['key_size', 'key_curve_name'],
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
