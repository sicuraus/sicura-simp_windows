# frozen_string_literal: true

require 'json'

Facter.add('unused_accounts') do
  confine operatingsystem: :windows
  setcode do
    fact_value ||= {}

    cur_date = JSON.parse(Facter::Core::Execution.execute('powershell.exe -noprofile -nologo -noninteractive -command "Get-Date | convertto-json"'))
    system_date_int = cur_date['value'].match(%r{\\?\/Date\((\d+)\)\\?\/})[1]
    fact_value['sys_date_int'] = system_date_int

    # rubocop:disable Metrics/LineLength
    ps_exec_cmd = if Facter.value(:simp_windows__facts)['active_directory']['systemrole'] == 'domaincontroller'
                    '(Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35 | Where-Object { $_.Enabled -eq $true } | select SamAccountName).Name | convertto-json'
                  else
                    '$output = @{};$enabledUsers = (Get-CimInstance -Class Win32_Useraccount -Filter \"LocalAccount=True and Disabled=False\" | Select-Object Name).Name;$enabledUsers | ForEach-Object {$user = ([ADSI](\'WinNT://{0}/{1}\' -f $env:COMPUTERNAME,$_));$lastLogin = $user.Properties.LastLogin.Value;if ($lastLogin -eq $null -or $lastlogin -lt (Get-Date).AddDays(-35)) {$output += @{$($user.Name) = $lastlogin}}};$output | convertto-json'
                  end
    ps_exec_string = "powershell.exe -noprofile -nologo -noninteractive -command \"#{ps_exec_cmd}\""
    # rubocopy:enable Metrics/LineLength
    ps_result = Facter::Core::Execution.execute(ps_exec_string)
    if ps_result == ''
      fact_value['accounts'] = {}
    else
      json_result = JSON.parse(ps_result)
      output = {}
      json_result.each do |key, value|
        date_int = if value.nil?
                     nil
                   else
                     value.match(%r{\\?\/Date\((\d+)\)\\?\/})[1]
                   end
        output[key] = date_int
      end
      fact_value['accounts'] = output
    end
    fact_value
  end
end
