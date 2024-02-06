# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json

try:
    from jinja2 import Environment
except ImportError as imp_exc:
    JINA2_IMPORT_ERROR = imp_exc
    Environment = None
else:
    JINA2_IMPORT_ERROR = None

from collections import defaultdict
from pathlib import Path

from ansible.module_utils.six import (
    iteritems, raise_from
)

from ansible.module_utils.parsing.convert_bool import (
    BOOLEANS_TRUE, BOOLEANS_FALSE
)


def process_json(data, template, raw=False):
    if JINA2_IMPORT_ERROR:
        raise_from(F5ModuleError('jinja2 package must be installed to use this collection'),
                   JINA2_IMPORT_ERROR
                   )
    jinja_env = Environment()
    template = jinja_env.from_string(template)
    content = template.render(params=data)
    if raw:
        return content
    my_json = json.loads(content)
    return my_json


def remove_extensions(filename):
    filename = Path(filename)
    if filename.suffixes:
        return remove_extensions(filename.stem)
    return filename.stem


def flatten_boolean(value):
    truthy = list(BOOLEANS_TRUE) + ['enabled', 'True', 'true']
    falsey = list(BOOLEANS_FALSE) + ['disabled', 'False', 'false']
    if value is None:
        return None
    elif value in truthy:
        return 'yes'
    elif value in falsey:
        return 'no'


def merge_two_dicts(x, y):
    """ Merge any two dicts passed to the function
        This does not do a deep copy, just a shallow
        copy. However, it does create a new object,
        so there's that.
    """
    z = x.copy()
    z.update(y)
    return z


class AnsibleF5Parameters:
    def __init__(self, *args, **kwargs):
        self._values = defaultdict(lambda: None)
        self._values['__warnings'] = None
        self.client = kwargs.pop('client', None)
        self._module = kwargs.pop('module', None)
        self._params = {}

        params = kwargs.pop('params', None)
        if params:
            self.update(params=params)
            self._params.update(params)

    def update(self, params=None):
        if params:
            self._params.update(params)
            for k, v in iteritems(params):
                if self.api_map is not None and k in self.api_map:
                    map_key = self.api_map[k]
                else:
                    map_key = k

                # Handle weird API parameters like `dns.proxy.__iter__` by
                # using a map provided by the module developer
                class_attr = getattr(type(self), map_key, None)
                if isinstance(class_attr, property):
                    # There is a mapped value for the api_map key
                    if class_attr.fset is None:
                        # If the mapped value does not have
                        # an associated setter
                        self._values[map_key] = v
                    else:  # pragma: no cover
                        # The mapped value has a setter
                        setattr(self, map_key, v)
                else:
                    # If the mapped value is not a @property
                    self._values[map_key] = v

    def api_params(self):
        result = {}
        for api_attribute in self.api_attributes:
            if self.api_map is not None and api_attribute in self.api_map:
                result[api_attribute] = getattr(self, self.api_map[api_attribute])
            else:
                result[api_attribute] = getattr(self, api_attribute)
        result = self._filter_params(result)
        return result

    def __getattr__(self, item):
        # Ensures that properties that weren't defined, and therefore stashed
        # in the `_values` dict, will be retrievable.
        return self._values[item]

    def _filter_params(self, params):
        return dict((k, v) for k, v in iteritems(params) if v is not None)


class F5ModuleError(Exception):
    pass
