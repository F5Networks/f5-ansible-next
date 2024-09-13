# BIG-IP Next Collection for Ansible

A collection focusing on managing BIG-IP Next devices through BIG-IP Next Central Manager (CM) API. The collection includes key imperative modules for 
deploying BIG-IP Next instances as well as modules to manage CM devices.

## Requirements

 - ansible >= 2.15

## Python Version
This collection is supported on Python 3.9 and above.

## Collections Daily Build

We offer a daily build of our most recent collection [dailybuild]. Use this Collection to test the most
recent Ansible module updates between releases. 
You can also install the development build directly from GitHub into your environment, see [repoinstall].

### Install from GitHub
```bash

ansible-galaxy collection install git+https://github.com/F5Networks/f5-ansible-next#ansible_collections/f5networks/next
```

### Install from the daily build file
```bash

    ansible-galaxy collection install <collection name> -p ./collections
    e.g.
    ansible-galaxy collection install f5networks-f5next-devel.tar.gz -p ./collections
```

> **_NOTE:_**  `-p` is the location in which the collection will be installed. This location should be defined in the path for
    Ansible to search for collections. An example of this would be adding ``collections_paths = ./collections``
    to your **ansible.cfg**

### Running latest devel in EE
We also offer a new method of running the collection inside Ansible's Execution Environment container. 
The advantage of such approach is that any required package dependencies and minimum supported Python versions are 
installed in an isolated container which minimizes any environment related issues during runtime. More information on EE
can be found here [execenv]. Use the below requirements.yml file when building EE container:

```yaml
---
collections:
  - name: ansible.netcommon
    version: ">=2.0.0"
  - name: f5networks.next
    source: https://github.com/F5Networks/f5-ansible-next#ansible_collections/f5networks/next
    type: git
    version: devel
```

Please see [f5execenv] documentation for further instructions how to use and build EE container with our devel branch.

## Bugs, Issues
   
Please file any bugs, questions, or enhancement requests by using [ansible_issues]. For details, see [ansiblehelp].

## Your ideas


What types of modules do you want created? If you have a use case and can sufficiently describe the behavior 
you want to see, open an issue and we will hammer out the details.

If you've got the time, consider sending an email that introduces yourself and what you do. 
We love hearing about how you're using the BIG-IP Next collection for Ansible.

> **_NOTE:_** **This repository is a mirror, only issues submissions are accepted.**

- Wojciech Wypior and the F5 team

## Copyright

Copyright 2024 F5 Networks Inc.


## License

### GPL V3

This License does not grant permission to use the trade names, trademarks, service marks, or product names of the 
Licensor, except as required for reasonable and customary use in describing the origin of the Work.

See [License].

### Contributor License Agreement
Individuals or business entities who contribute to this project must complete and submit the 
[F5 Contributor License Agreement] to ***Ansible_CLA@f5.com*** prior to their code submission 
being included in this project.


[repoinstall]: https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#installing-a-collection-from-a-git-repository
[dailybuild]: https://f5-ansible.s3.amazonaws.com/collections/f5networks-f5next-devel.tar.gz
[ansible_issues]: https://github.com/F5Networks/f5-ansible-next/issues
[License]: https://www.gnu.org/licenses/gpl-3.0.txt
[ansiblehelp]: http://clouddocs.f5.com/products/orchestration/ansible/devel/
[execenv]: https://docs.ansible.com/automation-controller/latest/html/userguide/execution_environments.html
[f5execenv]: http://clouddocs.f5.com/products/orchestration/ansible/devel/usage/exec-env.html
[F5 Contributor License Agreement]: http://clouddocs.f5.com/products/orchestration/ansible/devel/usage/contributor.html