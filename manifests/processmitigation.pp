# @summary Configures Windows Exploit Protection settings.
#
# Enforces configuration for Windows Exploit protection
#   settings for system and applications.
#
# @param mitigation
#   Mitigation setting.  Valid values are 'ON', 'OFF', 'NOT SET'. 
# @param applies_to
#   Executable name that the mitigation setting applies to.  Use 'System'
#   to set as global to the system.
# @example
#   simp_windows::processmitigation { 
#     'Data Execution Protection':
#       'applies_to': System
#       'mitigation': 
#         'DEP': 'ON'
#   }
#
# @example
#   simp_windows::processmitigation { 
#     'Data Execution Protection':
#       applies_to: 'FLTLDR.EXE'
#       mitigation: 
#         DEP: ON
#         BlockRemoteImageLoads: ON
#         EnableExportAddressFilter: ON
#         EnableExportAddressFilterPlus: ON
#         EnableImportAddressFilter: ON
#         EnableRopStackPivot: ON
#         EnableRopCallerCheck: ON
#         EnableRopSimExec: ON
#         DisallowChildProcessCreation: ON
#   }
define simp_windows::processmitigation (
  Hash[String, Enum['NOT SET', 'ON', 'OFF']] $mitigation,
  Variant[Enum['System'], Pattern[/(?i:\.exe)$/]]  $applies_to = $name,
) {

  $mitigationlookup = {
    'DEP'                                => 'Dep.Enable',
    'EmulateAtlThunks'                   => 'Dep.EmulateAtlThunks',
    'BottomUp'                           => 'Aslr.BottomUp',
    'ForceRelocateImages'                => 'Aslr.ForceRelocateImages',
    'RequireInfo'                        => 'Aslr.RequireInfo',
    'HighEntropy'                        => 'Aslr.HighEntropy',
    'StrictHandle'                       => 'StrictHandle.Enable',
    'DisableWin32kSystemCalls'           => 'SystemCall.DisableWin32kSystemCalls',
    'DisableExtensionPoints'             => 'ExtensionPoint.DisableExtensionPoints',
    'BlockDynamicCode'                   => 'DynamicCode.BlockDynamicCode',
    'AllowThreadsToOptOut'               => 'DynamicCode.AllowThreadsToOptOut',
    'CFG'                                => 'Cfg.Enable',
    'SuppressExports'                    => 'Cfg.SuppressExports',
    'StrictCFG'                          => 'Cfg.StrictControlFlowGuard',
    'MicrosoftSignedOnly'                => 'BinarySignature.MicrosoftSignedOnly',
    'AllowStoreSignedBinaries'           => 'BinarySignature.AllowStoreSignedBinaries',
    'EnforceModuleDependencySigning'     => 'BinarySignature.EnforceModuleDependencySigning',
    'DisableNonSystemFonts'              => 'FontDisable.DisableNonSystemFonts',
    'BlockRemoteImageLoads'              => 'ImageLoad.BlockRemoteImageLoads',
    'BlockLowLabelImageLoads'            => 'ImageLoad.BlockLowLabelImageLoads',
    'PreferSystem32'                     => 'ImageLoad.PreferSystem32',
    'EnableExportAddressFilter'          => 'Payload.EnableExportAddressFilter',
    'EnableExportAddressFilterPlus'      => 'Payload.EnableExportAddressFilterPlus',
    'AuditEnableExportAddressFilterPlus' => 'Payload.AuditEnableExportAddressFilterPlus',
    'EnableImportAddressFilter'          => 'Payload.EnableImportAddressFilter',
    'EnableRopStackPivot'                => 'Payload.EnableRopStackPivot',
    'EnableRopCallerCheck'               => 'Payload.EnableRopCallerCheck',
    'EnableRopSimExec'                   => 'Payload.EnableRopSimExec',
    'SEHOP'                              => 'SEHOP.Enable',
    'SEHOPTelemetry'                     => 'SEHOP.TelemetryOnly',
    'TerminateOnError'                   => 'Heap.TerminateOnError',
    'DisallowChildProcessCreation'       => 'ChildProcess.DisallowChildProcessCreation',
  }

  $factvalues = {
    'NOT SET' => 0,
    'ON'      => 1,
    'OFF'     => 2,
  }

  # Notify users if not setting "ON"
  $invalid_mitigations = $mitigation.filter |$value| { $value[1] != 'ON' }
  if $invalid_mitigations.length > 0 {
    notify { "${title}: Invalid setting specified.":
      message  => 'Setting mitigations to "OFF" or "NOT SET" is not currently implemented.  These settings will be added in future revisions.', # lint:ignore:140chars
      loglevel => 'warning',
    }
  }

  $execflag = $mitigation.any() |$key, $value| {  # returns false if test code ever evaluates to false, returns true if all are true

    $mitigationitem = $mitigationlookup[$key]
    $factvalue = $factvalues[$value]

    if $mitigationitem =~ Undef {
      fail ("${key} is not currently supported.")
    }

    $factsarray = $facts['simp_windows__facts']['process_mitigation'].filter |$element| {$element['ProcessName'] == $applies_to}
    if $factsarray.length > 0 {
      $hash = $factsarray[0]
    } else {
      $hash = {} #empty
    }

    $hashlevel1 = $mitigationitem.split('\.')[0]
    $hashlevel2 = $mitigationitem.split('\.')[1]

    $hash.dig($hashlevel1, $hashlevel2) != $factvalue
  }

  if $execflag {
    if $applies_to.downcase == 'system' {
      $setscope = '-system'
    } else {
      $setscope = "-Name ${applies_to}"
    }

    $mitigations_to_enable = $mitigation.reduce([]) |$memo, $value| {
        if $value[1] == 'ON' {
            $memo << $value[0]
        }
    }

    # Exec all settings if any do not match
    if $mitigations_to_enable.length > 0 {
        $mitigations_to_enable_string = $mitigations_to_enable.join(',')
    } else {
        $mitigations_to_enable_string = $mitigations_to_enable.flatten
    }

    if $mitigations_to_enable_string.length > 0 {
      exec { "${applies_to}-mitigation":
        command  => "set-processmitigation ${setscope} -enable ${mitigations_to_enable_string}",
        provider => powershell,
      }
    }
  }
}
