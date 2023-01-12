# simp_windows

#### Table of Contents

1. [Description](#description)
1. [Setup - The basics of getting started with simp_windows](#setup)
    * [What simp_windows affects](#what-simp_windows-affects)
    * [Setup requirements](#setup-requirements)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
1. [Limitations - OS compatibility, etc.](#limitations)

## Description

Provides functionality to apply SIMP compliance policies to Windows systems.

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
include '::simp_windows'
```

## Reference

See [REFERENCE.md](./REFERENCE.)
## Limitations

This module is supported on the following versions of Windows:
* Windows 2012
* Windows 2012 R2
* Windows Server 2016
* Windows Server 2019
* Windows Server 2022
