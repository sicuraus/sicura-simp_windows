# frozen_string_literal: true

require 'json'

Facter.add('non_expiring_accounts') do
  confine 'os.family' => 'windows'

  setcode do
    systemrole = Facter.value(:simp_windows__facts)['active_directory']['systemrole']
    ps_exec_cmd = if systemrole == 'domaincontroller'
                    '(Search-ADAccount -PasswordNeverExpires -UsersOnly | Where PasswordNeverExpires -eq True | Select Name).Name | ConvertTo-JSON'
                  else
                    '(Get-CimInstance -Class Win32_Useraccount -Filter \"PasswordExpires=False and LocalAccount=True and Disabled=False\" | Select Name).Name | ConvertTo-JSON'
                  end

    ps_exec_string = "powershell.exe -noprofile -nologo -noninteractive -command \"#{ps_exec_cmd}\""
    ps_result = Facter::Core::Execution.execute(ps_exec_string)
    if ps_result == ''
      []
    else
      json_result = JSON.parse(ps_result)
      if json_result.is_a?(String)
        output = []
        output << json_result
        output
      else
        json_result
      end
    end
  end
end
