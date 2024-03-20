#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: cm_ssl_certificate_import
short_description: Manages certificate, key and PKCS12 on the Central Manager.
description:
  - Manages certificate, key and PKCS12 on the Central Manager.
version_added: 1.0.0
options:
  name:
    description:
      - The name of the key and/or cert combination.
    type: str
    required: True
  cert:
    description:
      - The path to the certificate or PKCS12 file.
    type: path
  pkcs12_passphrase:
    description:
      - The passphrase for the PKCS12 cert file. It must be provided when importing a PKCS12 cert.
    type: str
  update_cert:
    description:
      - Whether to update the certificate on the Central Manager.
      - Set it to C(yes) when updating an existing certificate.
      - Not required when creating a new certificate.
    type: bool
    default: False
  key:
    description:
      - The path to the key file.
    type: path
  key_passphrase:
    description:
      - The passphrase for the key file.
    type: str
  update_key:
    description:
      - Whether to update the key on the Central Manager.
      - Set it to C(yes) when updating an existing key.
      - Not required when creating a new key.
    type: bool
    default: False
  type:
    description:
      - The type of the certificate.
    type: str
    choices:
      - PKCS12
      - PEM
  state:
    description:
      - When C(present), ensures the key and/or cert is uploaded to
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
  - Ravinder Reddy (@RavinderReddyF5)
  - Wojciech Wypior (@wojtek0806)
'''

EXAMPLES = r'''
'''

RETURN = r'''
name:
  description: The name of the key and/or cert combination.
  returned: changed
  type: str
  sample: testcert
cert:
  description: The path to the cert file.
  returned: changed
  type: str
  sample: /path/to/cert
key:
  description: The path to the key file.
  returned: changed
  type: str
  sample: /path/to/key
type:
  description: The type of the certificate.
  returned: changed
  type: str
  sample: PEM
'''

import base64
import hashlib
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ..module_utils.client import F5Client

from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, flatten_boolean
)

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class Parameters(AnsibleF5Parameters):
    api_map = {
        'cert_text': 'cert',
        'key_text': 'key',
        'import_type': 'type',
        'cert_passphrase': 'pkcs12_passphrase',
        'key_passphrase': 'key_passphrase',
    }

    api_attributes = [
        'cert_text',
        'key_text',
        'import_type',
        'cert_passphrase',
    ]

    returnables = [
        'name',
        'cert',
        'key',
        'pkcs12_passphrase',
        'key_passphrase',
        'type',
    ]

    updatables = [
        'cert',
        'key',
        'pkcs12_passphrase',
        'key_passphrase',
    ]


class ApiParameters(Parameters):
    @property
    def cert_checksum(self):
        if self._values.get('cert') is None:
            return None
        return self._values.get('cert').get('checksum')

    @property
    def key_checksum(self):
        if self._values.get('key') is None:
            return None
        return self._values.get('key').get('checksum')


class ModuleParameters(Parameters):
    def _get_hash(self, content):
        k = hashlib.sha512()
        s = StringIO(content)
        while True:
            data = s.read(1024)
            if not data:
                break
            k.update(data.encode('utf-8'))
        return k.hexdigest()

    def _read_pkcs_file(self, path):  # pragma: no cover
        with open(path, 'rb') as pfx_file:
            pfx_data = pfx_file.read()
        return base64.b64encode(pfx_data).decode()

    def _return_file_content(self, path):  # pragma: no cover
        with open(path, 'r') as file:
            data = file.read()
        return data

    @property
    def cert_checksum(self):
        if self.cert is None:
            return None
        return self._get_hash(self.cert)

    @property
    def key_checksum(self):
        if self.key is None:
            return None
        return self._get_hash(self.key)

    @property
    def cert(self):
        if self._values['cert'] is not None:
            if self.type == 'PKCS12':
                return self._read_pkcs_file(self._values['cert'])
            else:
                return self._return_file_content(self._values['cert'])

    @property
    def key(self):
        if self._values['key'] is not None:
            return self._return_file_content(self._values['key'])


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
    @property
    def cert(self):
        return ""

    @property
    def key(self):
        return ""


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
    def pkcs12_passphrase(self):
        return self.want.pkcs12_passphrase

    @property
    def cert(self):
        if flatten_boolean(self.want.update_cert) == 'no':
            return None

        if self.want.cert_checksum != self.have.cert_checksum:
            result = dict(
                checksum=self.want.cert_checksum,
                cert=self.want.cert
            )
            return result

    @property
    def key(self):
        if flatten_boolean(self.want.update_key) == 'no':
            return None

        if self.want.key_checksum != self.have.key_checksum:
            result = dict(
                checksum=self.want.key_checksum,
                key=self.want.key
            )
            return result


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
                    changed.update(change)
                else:
                    changed[k] = change  # pragma: no cover
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

    def create_on_device(self):
        params = self.changes.api_params()
        params['name'] = self.want.name
        uri = "/v1/spaces/default/certificates/import"

        self.log_message(f"Creating certificate {self.want.name}")
        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("Certificate created successfuly")
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        params['id'] = self.cert_id
        if params.get('cert_passphrase'):
            params['import_type'] = 'PKCS12'
        else:
            params['import_type'] = 'PEM'

        uri = "/v1/spaces/default/certificates/import"

        self.log_message(f"Updating certificate {self.want.name}")
        response = self.client.post(uri, params)

        if response['code'] not in [200, 201, 202]:
            raise F5ModuleError(response['contents'])

        self.log_message("Certificate updated successfuly")
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
                required=True
            ),
            cert=dict(
                type='path',
            ),
            update_cert=dict(
                type='bool',
                default=False
            ),
            key=dict(
                type='path',
            ),
            update_key=dict(
                type='bool',
                default=False
            ),
            pkcs12_passphrase=dict(
                type='str',
                no_log=True
            ),
            key_passphrase=dict(
                type='str',
                no_log=True
            ),
            type=dict(
                type='str',
                choices=['PKCS12', 'PEM'],
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
            ['type', 'PKCS12', ['pkcs12_passphrase']],
        ]
        self.required_one_of = [
            ['cert', 'key'],
        ]
        self.mutually_exclusive = [
            ['key', 'pkcs12_passphrase'],
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
