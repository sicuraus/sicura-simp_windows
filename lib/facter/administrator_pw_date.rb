# frozen_string_literal: true

# @summary Obtain the passwordlastset date for the built-in Administrator account
#
# Currently obtains:
#   * value of the PasswordLastSet attribute of the built-in Administrator account
#   * Current system date/time
#
# NOTE: The output may vary based on the target system
#
require 'json'

Facter.add('admin_pw_date') do
  confine 'os.family' => 'windows'

  setcode do
    fact_value ||= {}

    if Facter.value(:simp_windows__facts)['active_directory']['systemrole'] == 'domaincontroller'
      domain_id = Facter.value(:simp_windows__facts)['active_directory']['domain_id']
      admin_sid = "S-1-5-21-#{domain_id}-500"
      ps_exec_cmd = "(Get-ADUser -Identity #{admin_sid} -Property PasswordLastSet).passwordlastset | convertto-json"
      ps_exec_string = "powershell.exe -noprofile -nologo -noninteractive -command \"#{ps_exec_cmd}\""
      ps_date = JSON.parse(Facter::Core::Execution.execute(ps_exec_string))

      if ps_date.nil?
        raise 'admin_pw_date:: Error getting Administrator account details'
      end

      pw_date_int = ps_date['value'].match(%r{\\?\/Date\((\d+)\)\\?\/})[1]
      fact_value['pw_date_int'] = pw_date_int
      fact_value['pw_date'] = ps_date['DateTime']
    else
      account_name_cmd = '(Get-WmiObject -Class Win32_UserAccount -Filter \\"LocalAccount = \'True\' AND SID LIKE \'S-1-5-21-%-500\'\\").Name | convertto-json'
      admin_account_name = Facter::Core::Execution.execute("powershell.exe -noprofile -nologo -noninteractive -command \"#{account_name_cmd}\"")
      cmd_exec_string = "net user #{admin_account_name} | find \"Password last set\""
      exec_result = Facter::Core::Execution.execute(cmd_exec_string)
      acct_date = %r{(\d+)\/(\d+)\/(\d+) (\d+:\d+:\d+ [AP]M)}.match(exec_result)

      if acct_date.nil?
        raise 'admin_pw_date:: Error getting Administrator account details'
      end
      date_input = "#{acct_date[3]}-#{acct_date[1]}-#{acct_date[2]} #{acct_date[4]}"
      date_int = (DateTime.parse(date_input).to_time.to_i * 1000).to_s
      fact_value['pw_date_int'] = date_int
      fact_value['pw_date'] = acct_date[0]
    end

    cur_date = JSON.parse(Facter::Core::Execution.execute('powershell.exe -noprofile -nologo -noninteractive -command "Get-Date | convertto-json"'))
    system_date_int = cur_date['value'].match(%r{\\?\/Date\((\d+)\)\\?\/})[1]
    fact_value['sys_date_int'] = system_date_int
    fact_value['sys_date'] = cur_date['DateTime']

    fact_value
  end
end
