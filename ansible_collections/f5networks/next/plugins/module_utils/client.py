# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.constants import BASE_HEADERS, ROOT


def header(method):
    def wrap(self, *args, **kwargs):
        args = list(args)
        if 'scope' in kwargs:
            args[0] = kwargs['scope'] + args[0]
            kwargs.pop('scope')
        else:
            args[0] = ROOT + args[0]
        if 'headers' not in kwargs:
            kwargs['headers'] = BASE_HEADERS
            return method(self, *args, **kwargs)
        else:
            kwargs['headers'].update(BASE_HEADERS)
            return method(self, *args, **kwargs)
    return wrap


class F5Client:
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.plugin = kwargs.get('client', None)
        if self.plugin is not None and self.module is not None:
            self.plugin.init_logger(self.module._name)
        if self.module is not None and self.plugin is not None:
            self.plugin.update_secrets(list(self.module.no_log_values))

    @header
    def delete(self, url, body=None, **kwargs):
        return self.plugin.send_request(path=url, method='DELETE', payload=body, **kwargs)

    @header
    def get(self, url, **kwargs):
        return self.plugin.send_request(path=url, method='GET', **kwargs)

    @header
    def patch(self, url, body, **kwargs):
        return self.plugin.send_request(path=url, method='PATCH', payload=body, **kwargs)

    @header
    def post(self, url, body, **kwargs):
        return self.plugin.send_request(path=url, method='POST', payload=body, **kwargs)

    @header
    def put(self, url, body, **kwargs):
        return self.plugin.send_request(path=url, method='PUT', payload=body, **kwargs)

    def to_obfuscate(self):
        return self.plugin.return_no_log()
