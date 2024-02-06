vsphere = """
{
    "auto_failback": false,
    "cluster_management_ip": "{{ params.ha_ip }}",
    "cluster_name": "{{ params.ha_name }}",
    "control_plane_vlan": {
        "name": "{{ params.control_plane_vlan }}",
        "tag": {% if params.control_plane_vlan_tag is defined %}{{ params.control_plane_vlan_tag }}{% else %}0{% endif %}
    },
    "nodes": [
        {
            "name": "active-node",
            "control_plane_address": "{{ params.active_node_control_plane_ip }}",
            "data_plane_primary_address": "{{ params.active_node_data_plane_ip }}",
            "data_plane_secondary_address": ""
        },
        {
            "name": "standby-node",
            "control_plane_address": "{{ params.standby_node_control_plane_ip }}",
            "data_plane_primary_address": "{{ params.standby_node_data_plane_ip }}",
            "data_plane_secondary_address": ""
        }
    ],
    "standby_instance_id": "{{ params.standby_uuid }}",
    "data_plane_vlan": {
        "name": "{{ params.data_plane_vlan }}",
        "tag": {% if params.data_plane_vlan_tag is defined %}{{ params.data_plane_vlan_tag }}{% else %}0{% endif %},
        "NetworkInterface": "1.3"
    },
    "traffic_vlan": [
        {
            "name": "{{ params.external_vlan }}",{% if params.external_vlan_tag is defined %}
            "tag": {{ params.external_vlan_tag }},{% endif %}
            "networkInterface": "1.1",
            "networkName": "{{ params.external_network_name }}",
            "selfIps": [
                {
                    "address": "{{ params.floating_external_ip }}",
                    "instanceName": "FLOATING-IP"
                },
                {
                    "address": "{{ params.active_node_external_ip }}",
                    "instanceName": "ACTIVE-NODE"
                },
                {
                    "address": "{{ params.standby_node_external_ip }}",
                    "instanceName": "STANDBY-NODE"
                }
            ]
        },
        {
            "name": "{{ params.internal_vlan }}",
            "networkInterface": "1.2",
            "networkName": "{{ params.internal_network_name }}",{% if params.internal_vlan_tag is defined %}
            "tag": {{ params.internal_vlan_tag }},{% endif %}
            "selfIps": [
                {
                    "address": "{{ params.floating_internal_ip }}",
                    "instanceName": "FLOATING-IP"
                },
                {
                    "address": "{{ params.active_node_internal_ip }}",
                    "instanceName": "ACTIVE-NODE"
                },
                {
                    "address": "{{ params.standby_node_internal_ip }}",
                    "instanceName": "STANDBY-NODE"
                }
            ]
        }
    ]
}
"""
