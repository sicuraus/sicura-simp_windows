# @summary Apply SIMP compliance policies to Windows systems
#
# @param registry_values
#   Windows registry keys and values
# @param local_security_policies
#   Windows Local Security Policy settings
# @param audit_policies
#   Windows Audit Policy settings
# @param features
#   Windows Features settings
# @param acls
#   ACL settings
# @param services
#   Services
# @param reg_acls
#   Registry ACL settings
# @param modify_reg_acl_security
#   Modify the permissions of `HKLM\Security`
#   Due to Windows' tight control over the security key, this has been kept
#   seperate from the rest of the registry ACLs. Setting this paramater will
#   cause an error unless the module is run with SYSTEM level permissions.
# @param rename_admin_account
#   If set, rename the local `Administrator` account
# @param administrator_username
#   Username for the local `Administrator` user
# @param rename_guest_account
#   If set, rename the local `Guest` account
# @param guest_username
#   Username for the local `Guest` user
# @param enable_smart_card
#   Turn on Windows Smart Card Services
#   See also: 'simp_windows::smart_card'
# @param banner
#   Enable management of the login banner
# @param banner_name
#   Banner to use. By default, the options are `default`, `us_dod`, or `custom`.
# @param banner_custom_title
#   If `banner_name` is `custom`, use this title for the banner
# @param banner_custom_text If banner_type == 'custom'
#   If `banner_name` is `custom`, use this text for the banner
# @param banners
#   A hash containing possible banners
#
# @param manage_windows_firewall
#   Enable management of the Windows Firewall.  Firewall settings will only be changed if this is set to 'true'.
# @param windows_firewall
#   Hash of firewall settings to enforce.  See documentation in the puppet/windows_firewall module for details.
#   Link: https://forge.puppet.com/modules/puppet/windows_firewall
# @param windows_firewall_exceptions
#   Hash of firewall rules to enforce.
#   Example rule:
#      'WINRM':
#        ensure       => present,
#        direction    => 'in',
#        action       => 'allow',
#        enabled      => true,
#        protocol     => 'TCP',
#        local_port   => 5985,
#        remote_port  => 'any',
#        display_name => 'Windows Remote Management HTTP-In',
#        description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
#
# @param install_emet
#   Deploys Microsoft Enhanced Mitigation Experience Toolkit v5.52 to clients
# @param install_laps
#   Deploys Microsoft Local Administrator Password Solution GPO CSE to clients
#   NOTE: The Active Directory Schema must be extended and permissions configured
#     as described in the LAPS Operations Guide, which can be found at 
#     https://www.microsoft.com/en-us/download/details.aspx?id=46899.  The CSE will have no effect
#     on clients until those prerequisites are completed and Group Policy configured to enable the
#     solution.
# @param processmitigation
#   A hash containing process mitigation settings.
#   See simp_windows::processmitigation for details.
# @param krbtgt_pw_date
#   A hash containing settings for krbtgt account password age
#   See simp_windows::krbtgt_pw_date for details.
# @param administrator_pw_date
#   A hash containing settings for built-in Administrator account password age
#   See simp_windows::administrator_pw_date for details.
# @param password_expiry
#   A boolean to enable checking for accounts with 'Password never expires' enabled
# @param password_expiry_exclusions
#   An array containing account names allowed to have 'Password never expires' enabled
# @param unused_accounts
#   Detect and notify on unused accounts
# @param unused_accounts_maxdays
#   Number of days after which an account is considered 'unused'
# @param unused_accounts_exclusions
#   Array containing account names to exclude from alerting
# @param classes
#   An array containing the classes listed in simp::classes
class simp_windows (
  Hash                    $registry_values,
  Hash                    $local_security_policies,
  Hash                    $audit_policies,
  Hash                    $features,
  Hash                    $acls,
  Hash                    $services,
  Hash                    $reg_acls,
  Boolean                 $modify_reg_acl_security,
  Boolean                 $enable_smart_card,
  Boolean                 $rename_admin_account,
  Optional[String[1,104]] $administrator_username,
  Boolean                 $rename_guest_account,
  Optional[String[1,104]] $guest_username,
  Boolean                 $banner,
  String                  $banner_name,
  String                  $banner_custom_title,
  String                  $banner_custom_text,
  Hash                    $banners,
  Hash                    $processmitigation,
  Hash                    $krbtgt_pw_date,
  Hash                    $administrator_pw_date,
  Boolean                 $password_expiry,
  Array                   $password_expiry_exclusions,
  Boolean                 $unused_accounts,
  Numeric                 $unused_accounts_maxdays,
  Array                   $unused_accounts_exclusions,
  Boolean                 $manage_windows_firewall,
  Hash                    $windows_firewall,
  Hash                    $windows_firewall_exceptions,
  Boolean                 $install_emet,
  Boolean                 $install_laps,
  # lint:ignore:lookup_in_parameter
  Array                   $classes = lookup('simp::classes', Array[String], 'unique', []),
  # lint:endignore
) {
  # include all classes in simp::classes
  # unless they start with the knockout prefix '--'
  $included_classes = $classes.filter |$c| { $c !~ /^--/ }
  $excluded_classes = $classes.filter |$c| { $c =~ /^--/ }.map |$c| { $c.regsubst(/^--/, '') }

  $_classes = $included_classes - $excluded_classes

  include $_classes

  # SMART CARD MANAGEMENT
  if $enable_smart_card {
    include simp_windows::smart_card
    $_smart_card_local_policy = {
      'Interactive logon: Smart card removal behavior' => {},
      'Interactive logon: Require smart card'          => {},
    }
  } else {
    $_smart_card_local_policy = {}
  }

  # BANNER MANAGEMENT
  if $banner {
    if $banner_name == 'custom' {
      $banner_text = $banner_custom_text
      $banner_title = $banner_custom_title
    } else {
      $banner_text = $banners[$banner_name]['data']
      $banner_title = $banners[$banner_name]['title']
    }
    # Windows needs the banner in a weird comma deliminated format, and can't handle empty lines easily
    $converted_banner = $banner_text.chomp.regsubst(',', '","', 'G').regsubst('\n+', ',', 'G')

    $_banner_security_policy = {
      'Interactive logon: Message title for users attempting to log on' => {
        'policy_value' => "1,\"${banner_title}\"",
      },
      'Interactive logon: Message text for users attempting to log on'  => {
        'policy_value' => "7,${converted_banner}",
      },
    }
  } else {
    $_banner_security_policy = {}
  }

  # ACCOUNT NAME MANAGEMENT
  if $rename_admin_account {
    $_admin_account_security_policy = {
      'Accounts: Rename administrator account' => {
        'policy_value' => "\"${administrator_username}\"",
      },
    }
  } else {
    $_admin_account_security_policy = {}
  }

  if $rename_guest_account {
    $_guest_account_security_policy = {
      'Accounts: Rename guest account' => {
        'policy_value' => "\"${guest_username}\"",
      },
    }
  } else {
    $_guest_account_security_policy = {}
  }

  # Registry Values
  $registry_values.each |String $key, Hash $data| {
    $res_name = "${data['key']}\\${data['value']}"

    if $data['ensure'] == 'absent' {
      registry_value { $res_name:
        ensure => $data['ensure'],
        path   => $res_name,
      }
    } else {
      registry::value { $res_name:
        key   => downcase($data['key']),
        value => $data['value'],
        type  => $data['type'],
        data  => $data['data'],
      }
    }
  }

  # Registry ACL Permissions
  $reg_acls.each |String $key, Hash $data| {
    reg_acl { $data['target']:
      * => $data,
    }
  }

  # Due to Windows' tight control over the security key, this has been kept s
  # seperate from the rest of the reg ACLs. This will error out unless the module
  # is run with SYSTEM level permissions.
  if $modify_reg_acl_security {
    reg_acl { 'security':
      target              => 'hklm:security',
      owner               => 'Administrators',
      purge               => 'all',
      inherit_from_parent => false,
      permissions         => [
        { 'RegistryRights' => 'ReadPermissions', 'IdentityReference' => 'Administrators' },
        { 'RegistryRights' => 'ChangePermissions', 'IdentityReference' => 'Administrators' },
        { 'RegistryRights' => 'FullControl', 'IdentityReference' => 'SYSTEM' },
      ],
    }
  }

  # ACL Permissions
  $acls.each |String $key, Hash $data| {
    acl { $data['target']:
      * => $data,
    }
  }

  # Services
  $services.each |String $key, Hash $data| {
    if $data['name'] in $facts['service_list'] {
      service { $data['name'] :
        * => $data,
      }
    }
  }

  # Security Policies
  $_merged_local_security_policies = $local_security_policies +
  $_banner_security_policy +
  $_admin_account_security_policy +
  $_guest_account_security_policy -
  $_smart_card_local_policy

  $_merged_local_security_policies.each |String $key, Hash $data| {
    local_security_policy { $key:
      * => $data,
    }
  }

  # Audit policies
  $audit_policies.each |String $audit_name, Hash $audit_data| {
    auditpol { $audit_name:
      * => $audit_data,
    }
  }

  # Windows Features
  $features.each |String $feature_name, Hash $feature_data| {
    windowsfeature { $feature_name:
      * => $feature_data,
    }
  }

  # Windows Exploit Protection
  $processmitigation.reduce({}) |Hash $memo, Array $value| {
    $applies_to = dig($value, 1, 'applies_to')

    if $applies_to == undef {
      $key = $value[0].downcase
    } else {
      $key = $applies_to.downcase
    }

    deep_merge($memo, { $key => $value[1] })
  }.each |String $mitigation_name, Hash $mitigation_data| {
    simp_windows::processmitigation { $mitigation_name:
      * => $mitigation_data,
    }
  }

  # krbtgt account password age
  $krbtgt_pw_date.each |String $setting_name, Hash $setting_data| {
    simp_windows::krbtgt_pw_date { $setting_name:
      * => $setting_data,
    }
  }

  # Administrator account password age
  $administrator_pw_date.each |String $key, Hash $data| {
    simp_windows::administrator_pw_date { $key:
      * => $data,
    }
  }

  # Password expiration
  if $password_expiry {
    #include simp_windows::password_expiry
    class { 'simp_windows::password_expiry':
      exclusions => $password_expiry_exclusions,
    }
  }

  # Unused accounts
  if $unused_accounts {
    #include simp_windows::unused_accounts
    class { 'simp_windows::unused_accounts':
      exclusions => $unused_accounts_exclusions,
      maxdays    => $unused_accounts_maxdays,
    }
  }

  # Windows Firewall
  if $manage_windows_firewall {
    include 'windows_firewall'

    $windows_firewall.each |String $key, Hash $data| {
      windowsfirewall { $key:
        * => $data,
      }
    }

    $windows_firewall_exceptions.each |String $key, Hash $data| {
      windows_firewall::exception { $key:
        * => $data,
      }
    }
  }

  # Enhanced Mitigation Experience Toolkit
  if $install_emet {
    include 'simp_windows::emet'
  }

  # Local Administrator Password Solution
  if $install_laps {
    include 'simp_windows::laps'
  }
}
