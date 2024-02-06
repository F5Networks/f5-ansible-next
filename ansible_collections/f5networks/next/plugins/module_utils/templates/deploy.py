vsphere = """
{
    "template_name": "default-standalone-ve",
    "parameters": {
        "hostname": "{{ params.instance_hostname }}",
        "instantiation_provider": [
            {
                "id": "{{ params.provider_id }}",
                "type": "vsphere",
                "name": "{{ params.provider_name }}"
            }
        ],
        "vSphere_properties": [
            {
                "cluster_name": "{{ params.cluster }}",
                "datacenter_name": "{{ params.datacenter }}",
                "resource_pool_name": "{{ params.resource_pool }}",
                "datastore_name": "{{ params.datastore }}",
                "vsphere_content_library": "{{params.content_lib }}",
                "vm_template_name": "{{ params.template }}",
                "num_cpus": {{ params.cpus }},
                "memory": {{ params.memory }}
            }
        ],
        "management_address": "{{ params.mgmt_address}}",
        "management_network_width": {{ params.mgmt_net_width }},
        "default_gateway": "{{ params.mgmt_gw }}",
        "vsphere_network_adapter_settings": [
            {
                "mgmt_network_name": "{{ params.mgmt_net_name }}",
                "external_network_name": "{{ params.ext_net_name }}"{% if params.int_net_name is defined %},
                "internal_network_name": "{{ params.int_net_name}}"{% endif %}{% if params.ha_dp_network_name is defined %},
                "ha_data_plane_network_name": "{{ params.ha_dp_network_name}}",
                "ha_control_plane_network_name": ""{% endif %}
            }
        ],
        "dns_servers": {% if params.dns is defined %}{{ params.dns | tojson }}{% else %}[]{% endif %},
        "ntp_servers": {% if params.ntp is defined %}{{ params.ntp | tojson }}{% else %}[]{% endif %},
        "l1Networks": [
            {
                "l1Link": {
                    "linkType": "Interface",
                    "name": "1.1"
                },
                "name": "{{ params.ext_net_name }}"{% if params.ext_vlan_name is defined %},
                "vlans": [
                    { {% if params.ext_ip_addr is defined %}
                        "selfIps": [
                            {
                                "address": "{{ params.ext_ip_addr }}"
                            }
                        ],{% endif %}{% if params.ext_vlan_tag is defined %}
                        "tag": {{ params.ext_vlan_tag }},{% endif %}
                        "name": "{{ params.ext_vlan_name }}"
                    }
                ]{% endif %}
            }{% if params.int_net_name is defined %},
            {
                "l1Link": {
                    "linkType": "Interface",
                    "name": "1.2"
                },
                "name": "{{ params.int_net_name }}"{% if params.int_vlan_name is defined %},
                "vlans": [
                    {
                      {% if params.int_ip_addr is defined %}
                        "selfIps": [
                            {
                                "address": "{{ params.int_ip_addr }}"
                            }
                        ],{% endif %}{% if params.int_vlan_tag is defined %}
                        "tag": {{ params.int_vlan_tag }},{% endif %}
                        "name": "{{ params.int_vlan_name }}"
                    }
                ]{% endif %}
            }{% endif %}

        ],
        "management_credentials_username": "{{ params.mgmt_user }}",
        "management_credentials_password": "{{ params.mgmt_password }}",
        "instance_one_time_password": "{{ params.mgmt_password }}"
    }
}"""


rseries = """
{
    "template_name": "default-standalone-rseries",
    "parameters": {
        "instantiation_provider": [
            {
                "id": "{{ params.provider_id }}",
                "name": "{{ params.provider_name }}",
                "type": "rseries"
            }
        ],
        "rseries_properties": [
            {
                "tenant_image_name": "{{ params.image_name }}",
                "tenant_deployment_file": "{{ params.image_name }}.yaml",
                "vlan_ids": {% if params.vlans is defined %}{{ params.vlans | tojson }}{% else %}[]{% endif %},
                "disk_size": {{ params.disk_size }},
                "cpu_cores": {{ params.cpus }}
            }
        ],
        "management_address": "{{ params.mgmt_address}}",
        "management_network_width": {{ params.mgmt_net_width }},
        "default_gateway": "{{ params.mgmt_gw }}",
        "l1Networks": [
            {
                "vlans": [
                    {
                        "selfIps": [],
                        "name": "{{ params.ha_cp_vlan_name }}"{% if params.ha_cp_vlan_tag is defined %},
                        "tag": {{ params.ha_cp_vlan_tag }}{% endif %}
                    },
                    {
                        "selfIps": [],
                        "name": "{{ params.ha_dp_vlan_name }}"{% if params.ha_dp_vlan_tag is defined %},
                        "tag": {{ params.ha_dp_vlan_tag }}{% endif %}
                    },
                    {
                        "selfIps": {% if params.ext_ip_addr is defined %}[
                            {
                                "address": "{{ params.ext_ip_addr }}"
                            }
                        ]{% else %}[]{% endif %},
                        "name": "{{ params.ext_vlan_name }}"{% if params.ext_vlan_tag is defined %},
                        "tag": {{ params.ext_vlan_tag }}{% endif %}
                    },
                    {
                        "selfIps": {% if params.int_ip_addr is defined %}[
                            {
                                "address": "{{ params.int_ip_addr }}"
                            }
                        ]{% else %}[]{% endif %},
                        "name": "{{ params.int_vlan_name }}"{% if params.int_vlan_tag is defined %},
                        "tag": {{ params.int_vlan_tag }}{% endif %}
                    }
                ],
                "l1Link": {
                    "linkType": "Interface",
                    "name": "1.1"
                },
                "name": "{{ params.ext_net_name }}"
            }
        ],
        "management_credentials_username": "{{ params.mgmt_user }}",
        "management_credentials_password": "{{ params.mgmt_password }}",
        "instance_one_time_password": "{{ params.mgmt_password }}",
        "hostname": "{{ params.instance_hostname }}"
    }
}"""
