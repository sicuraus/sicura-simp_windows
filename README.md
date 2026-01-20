# simp_windows

#### Table of Contents

- [simp\_windows](#simp_windows)
      - [Table of Contents](#table-of-contents)
  - [Description](#description)
  - [Setup](#setup)
    - [What simp\_windows affects](#what-simp_windows-affects)
    - [Setup Requirements](#setup-requirements)
  - [Usage](#usage)
  - [Reference](#reference)
  - [Limitations](#limitations)

## Description

Provides functionality to apply Sicura compliance policies to Windows systems.

## Setup

### What simp_windows affects

This provides management capabilites over the following areas:

* Audit Policies
* File System permissions
* Local Security Policies
* Process Mitigation
* Registry permissions
* Registry values
* Windows Features installation
* Windows Firewall

### Setup Requirements

This module requires the following:
* [ayohrling-local_security_policy](https://forge.puppet.com/ayohrling/local_security_policy)
* [fervid-auditpol](https://forge.puppet.com/fervid/auditpol)
* [ipcrm-registry_acl](https://forge.puppet.com/ipcrm/registry_acl)
* [simp-simplib](https://forge.puppet.com/simp/simplib)
* [puppetlabs-acl](https://forge.puppet.com/modules/puppetlabs/acl)
* [puppetlabs-powershell](https://forge.puppet.com/puppetlabs/powershell)
* [puppetlabs-registry](https://forge.puppet.com/puppetlabs/registry)
* [puppetlabs-stdlib](https://forge.puppet.com/puppetlabs/stdlib)
* [puppet-windowsfeature](https://forge.puppet.com/puppet/windowsfeature)
* [puppet-windows_firewall](https://forge.puppet.com/puppet/windows_firewall)

## Usage

```puppet
include 'simp_windows'
```

## Reference

See [REFERENCE.md](./REFERENCE.)

## Limitations

This module is supported on the following versions of Windows:
* Windows Server 2016
* Windows Server 2019
* Windows Server 2022
* Windows Server 2025
* Windows 11
