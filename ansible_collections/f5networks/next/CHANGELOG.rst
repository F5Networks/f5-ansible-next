==================================================
F5Networks F5 BIG-IP Next Collection Release Notes
==================================================

.. contents:: Topics

v1.0.0
======

Bugfixes
--------

- cm_next_discover - fixed a bug to add bigip next instance onto central manager INFRAANO-1510

New Plugins
-----------

Httpapi
~~~~~~~

- cm - HttpApi Plugin for BIG-IP Next Central Manager devices

New Modules
-----------

- cm_device_info - Collect information from CM devices
- cm_files - Manage files uploads/deletes on BIG-IP Next CM
- cm_next_as3_deploy - Manages Deploying an AS3 declaration to a specified instance managed by BIG-IP Next Central Manager.
- cm_next_backup_restore - Backup and restore BIG-IP Next instance configration through CM
- cm_next_deploy_f5os - Module to manage deployments of BIG-IP Next instances on F5OS devices
- cm_next_deploy_vmware - Module to manage deployments of BIG-IP Next instances on VMWARE
- cm_next_discover - Module to Add/Delete BIG-IP Next Instances onto Central Manager
- cm_next_files - Manage BIG-IP Next instance files through CM
- cm_next_global_resiliency_group - Manages Global Resiliency Group on the Central Manager.
- cm_next_ha - Configure High Availability for BIG-IP Next instances.
- cm_next_ha_failover - Fail-over BIG-IP Next HA instance on CM
- cm_next_provider - Manage providers on Central Manager
- cm_next_upgrade - Manage BIG-IP Next instance upgrades through CM
- cm_ssl_certificate_create - Manages certificate and/or key on the Central Manager.
- cm_ssl_certificate_import - Manages certificate, key and PKCS12 on the Central Manager.
