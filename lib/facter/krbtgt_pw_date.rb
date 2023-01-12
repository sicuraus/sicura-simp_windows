# frozen_string_literal: true

# @summary Obtain the passwordlastset date for the krbtgt account
#
# Currently obtains:
#   * value of the PasswordLastSet attribute of krbtgt
#   * Current system date/time
#
# NOTE: The output may vary based on the target system
#
require 'json'
Facter.add('krbtgt_pw_date') do
  confine osfamily: :windows

  setcode do
    if dig(Facter.value(:simp_windows__facts), 'active_directory', 'systemrole') == 'domaincontroller'
      fact_value ||= {}

      ps_command = 'powershell.exe -noprofile -nologo -noninteractive -command "(Get-ADUser krbtgt -Property PasswordLastSet).passwordlastset | convertto-json"'
      ps_date = JSON.parse(Facter::Core::Execution.execute(ps_command))
      if ps_date.nil?
        raise 'krbtgt_pw_date:: Error getting krbtgt account details'
      end

      pw_date_int = ps_date['value'].match(%r{\\?\/Date\((\d+)\)\\?\/})[1]
      fact_value['pw_date_int'] = pw_date_int
      fact_value['pw_date'] = ps_date['DateTime']

      cur_date = JSON.parse(Facter::Core::Execution.execute('powershell.exe -noprofile -nologo -noninteractive -command "Get-Date | convertto-json"'))
      system_date_int = cur_date['value'].match(%r{\\?\/Date\((\d+)\)\\?\/})[1]
      fact_value['sys_date_int'] = system_date_int
      fact_value['sys_date'] = cur_date['DateTime']

      fact_value
    else
      false
    end
  rescue
    false
  end
end
