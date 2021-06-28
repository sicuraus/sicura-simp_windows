# @summary Configures the system to use smart cards
#
# @param ensure
#   Define enforcement state
#   Possible options are 'present' and 'absent'.  Defaults to 'present'.
# @param enable
#   A boolean for the desired state of the 'SCPolicySvc' service.  Defaults to true.
# @param lock_on_removal
#   A boolean for the desired state of the 'Interactive logon: Smart card removal behavior' setting
#   Defaults to true.
# @param require_smart_card
#   A boolean for the desired state of the 'Interactive logon: Require smart card' setting
#   Defaults to false.
#
class simp_windows::smart_card (
  Enum['present','absent'] $ensure             = 'present',
  Boolean                  $enable             = true,
  Boolean                  $lock_on_removal    = true,
  Boolean                  $require_smart_card = false
) {

  if $lock_on_removal {
    $_removal_value = '"1"'
  }
  else {
    $_removal_value = '0'
  }

  local_security_policy { 'Interactive logon: Smart card removal behavior':
    ensure       => 'present',
    policy_value => $_removal_value,
  }

  if $require_smart_card {
    $_require_value = '1'
  }
  else {
    $_require_value = '0'
  }

  local_security_policy { 'Interactive logon: Require smart card':
    ensure       => 'present',
    policy_value => $_require_value,
  }

  $_svc_ensure = $enable ? { true => 'running', false => 'stopped' }
  service { 'SCPolicySvc':
    ensure => $_svc_ensure,
    enable => $enable,
  }
}
