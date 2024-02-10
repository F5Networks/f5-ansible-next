# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import unittest
import logging
from unittest.mock import patch
from ansible_collections.f5networks.next.plugins.module_utils.logging import (
    CustomFormatter, return_logger, sanitize_sensitive_data
)


class TestCustomFormatter(unittest.TestCase):
    def test_format(self):
        formatter = CustomFormatter()
        record = logging.LogRecord('test', logging.INFO, __file__, 42, 'Test message', (), None)

        with patch('time.time', return_value=1234567890):
            formatted_output = formatter.format(record)

        expected_output = '\n==================== New Logging Session ====================\n Test message'
        self.assertEqual(formatted_output, expected_output)

        # Simulate a log record within the same session
        with patch('time.time', return_value=1234567890):
            formatted_output = formatter.format(record)

        expected_output = ' Test message'
        self.assertEqual(formatted_output, expected_output)


class TestReturnLogger(unittest.TestCase):
    def test_return_logger(self):
        logger = return_logger('test-mod')
        self.assertIsInstance(logger, logging.Logger)


class TestSanitizeSensitiveData(unittest.TestCase):
    def test_sanitize_sensitive_data_string(self):
        data = "This is a sensitive data example."
        sensitive_values = ["sensitive", "example"]
        sanitized_data = sanitize_sensitive_data(data, sensitive_values)
        expected_data = "This is a ********* data *******."

        self.assertEqual(sanitized_data, expected_data)

    def test_sanitize_sensitive_data_list(self):
        data = ["sensitive", "data", "example"]
        sensitive_values = ["sensitive", "example"]
        sanitized_data = sanitize_sensitive_data(data, sensitive_values)
        expected_data = ["*********", "data", "*******"]

        self.assertEqual(sanitized_data, expected_data)

    def test_sanitize_sensitive_data_dict(self):
        data = {"key1": "sensitive", "key2": "example", "key3": "data"}
        sensitive_values = ["sensitive", "example"]
        sanitized_data = sanitize_sensitive_data(data, sensitive_values)
        expected_data = {"key1": "*********", "key2": "*******", "key3": "data"}

        self.assertEqual(sanitized_data, expected_data)

    def test_sanitize_sensitive_data_invalid_input(self):
        with self.assertRaises(TypeError):
            sanitize_sensitive_data("data", "sensitive_value")
