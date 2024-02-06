# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import logging
import tempfile
import datetime


class CustomFormatter(logging.Formatter):
    def __init__(self, fmt=None):
        super().__init__(fmt)
        self.last_session_start = None

    def format(self, record):
        # Check if it's the start of a new logging session and add session separator
        current_session_start = record.created // 3600
        if current_session_start != self.last_session_start:
            self.last_session_start = current_session_start
            session_separator = f'\n{"=" * 20} New Logging Session {"=" * 20}\n'
        else:
            session_separator = ''

        # if mod argument is not present in extra we sub it for N/A
        if 'mod' in record.__dict__:
            record.mod = record.__dict__['mod']
        else:
            record.mod = 'N/A'

        formatted_record = super().format(record)
        return f'{session_separator} {formatted_record}'


def return_logger(mod_name):
    temp_dir = tempfile.gettempdir()
    log_file_path = os.path.join(temp_dir, f"{mod_name}-{datetime.datetime.now()}-debug.log")
    file_handler = logging.FileHandler(log_file_path)
    logger = logging.getLogger('F5 LOGGER')
    logger.propagate = False
    formatter = CustomFormatter('%(asctime)s - %(levelname)s - %(mod)s - %(funcName)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def sanitize_sensitive_data(data, sensitive_values, replace_char='*'):
    if not isinstance(sensitive_values, list):
        raise TypeError("sensitive_values must be a list of strings")
    if isinstance(data, str):
        for value in sensitive_values:
            data = data.replace(value, replace_char * len(value))
    elif isinstance(data, (dict, list)):
        if isinstance(data, dict):
            data = {k: sanitize_sensitive_data(v, sensitive_values, replace_char) for k, v in data.items()}
        elif isinstance(data, list):
            data = [sanitize_sensitive_data(item, sensitive_values, replace_char) for item in data]
    return data
