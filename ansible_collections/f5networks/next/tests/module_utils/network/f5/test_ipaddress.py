# -*- coding: utf-8 -*-
#
# Copyright (c) 2023 F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import unittest
from ansible_collections.f5networks.next.plugins.module_utils.ipaddress import (
    is_valid_cidr, is_valid_ip, is_valid_ip_network, is_valid_ip_interface
)


class TestNetworkFunctions(unittest.TestCase):
    def test_is_valid_cidr(self):
        valid_cidrs = ['192.168.1.0/24', '2001:db8::/32']
        invalid_cidrs = ['192.168.1.0/33', '2001:db8::']

        for valid_cidr in valid_cidrs:
            self.assertTrue(is_valid_cidr(valid_cidr))

        for invalid_cidr in invalid_cidrs:
            self.assertFalse(is_valid_cidr(invalid_cidr))

    def test_is_valid_ip(self):
        valid_ipv4_addresses = ['192.168.1.1', '10.0.0.1']
        invalid_ipv4_addresses = ['192.168.1.256', 'invalid']

        valid_ipv6_addresses = ['2001:db8::1', 'fe80::1']
        invalid_ipv6_addresses = ['2001:db8:::1', 'invalid']

        for valid_ipv4 in valid_ipv4_addresses:
            self.assertTrue(is_valid_ip(valid_ipv4, 'ipv4'))

        for invalid_ipv4 in invalid_ipv4_addresses:
            self.assertFalse(is_valid_ip(invalid_ipv4, 'ipv4'))

        for valid_ipv6 in valid_ipv6_addresses:
            self.assertTrue(is_valid_ip(valid_ipv6, 'ipv6'))

        for invalid_ipv6 in invalid_ipv6_addresses:
            self.assertFalse(is_valid_ip(invalid_ipv6, 'ipv6'))

    def test_is_valid_ip_network(self):
        valid_ip_networks = ['192.168.1.0/24', '2001:db8::/32']
        invalid_ip_networks = ['192.168.1.0/2', 'invalid_ipv6_network']

        for valid_network in valid_ip_networks:
            self.assertTrue(is_valid_ip_network(valid_network))

        for invalid_network in invalid_ip_networks:
            self.assertFalse(is_valid_ip_network(invalid_network))

    def test_is_valid_ip_interface(self):
        valid_ip_interfaces = ['192.168.1.1/24', '2001:db8::1/32']
        invalid_ip_interfaces = ['300.168.1.1', 'invalid_ipv6_address']

        for valid_interface in valid_ip_interfaces:
            self.assertTrue(is_valid_ip_interface(valid_interface))

        for invalid_interface in invalid_ip_interfaces:
            self.assertFalse(is_valid_ip_interface(invalid_interface))
