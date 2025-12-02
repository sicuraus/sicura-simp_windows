# frozen_string_literal: true

# @summary Obtain information about the Windows artifacts on the system
#
# Currently obtains:
#   * All items from Win32_ComputerSystem
#   * The Domain identifier
#
# NOTE: The output may vary based on the target system
#

Facter.add('simp_windows__facts') do
  confine 'os.family' => 'windows'

  # Obtain the Win32_ComputerSystem information as a hash
  #
  # @return [Hash]
  #   All properties and values or `nil` if nothing could be obtained
  #
  def fetch_sys_info
    sys_info = {}

    begin
      require 'win32ole'

      wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')

      wmi_result = wmi.ExecQuery('SELECT * FROM Win32_ComputerSystem')

      properties = []

      wmi_result.each do |info|
        info.Properties_.each do |prop|
          properties << prop.Name
        end
        break
      end

      wmi_result = wmi_result.to_enum.first
      properties.each do |prop|
        property = wmi_result.send(prop)

        # Some items return nil and should not be included
        if property
          sys_info[prop] = property
        end
      end
    rescue => e
      Facter.warn("Error processing Win32_ComputerSystem => #{e}")
    end

    sys_info
  end

  # Takes the output of #fetch_sys_info and returns derived domain-centric data
  #
  # @return [Hash]
  #   Domain-centtric data
  #
  def fetch_domain_info(sys_info)
    domain_info = nil

    if sys_info && sys_info['DomainRole']
      domain_info = {
        'winsystype' => nil,
        'systemrole' => nil,
        'joined'     => false,
        'domain'     => false,
        'domain_id'  => nil,
      }

      case sys_info['DomainRole']
      when 0
        domain_info['winsystype'] = 'workstation'
        domain_info['systemrole'] = 'standaloneworkstation'
        domain_info['joined'] = false
        domain_info['domain'] = false
      when 1
        domain_info['winsystype'] = 'workstation'
        domain_info['systemrole'] = 'memberworkstation'
        domain_info['joined'] = true
        domain_info['domain'] = sys_info['Domain']
      when 2
        domain_info['winsystype'] = 'server'
        domain_info['systemrole'] = 'standaloneserver'
        domain_info['joined'] = false
        domain_info['domain'] = false
      when 3
        domain_info['winsystype'] = 'server'
        domain_info['systemrole'] = 'memberserver'
        domain_info['joined'] = true
        domain_info['domain'] = sys_info['Domain']
      when 4, 5
        domain_info['winsystype'] = 'domaincontroller'
        domain_info['systemrole'] = 'domaincontroller'
        domain_info['joined'] = true
        domain_info['domain'] = sys_info['Domain']
      else
        domain_info['winsystype'] = nil
        domain_info['systemrole'] = nil
        domain_info['joined'] = nil
        domain_info['domain'] = nil
      end

      if domain_info['joined']
        begin
          require 'puppet/util/windows/sid'

          domain_regex = %r{^S-1-5-21-(?<domain_id>.+)-512$}

          matches = Puppet::Util::Windows::SID.name_to_sid('Domain Admins').match(domain_regex)

          domain_info['domain_id'] = matches[:domain_id] if matches
        rescue => e
          Facter.warn("Error getting SID of 'Domain Admins' for domain '#{domain_info['domain']}' => #{e}")
        end
      end
    end
    domain_info
  end

  def fetch_exploit_protection_info
    # app_process_mitigation = Facter::Core::Execution.execute('powershell.exe -noprofile -nologo -noninteractive -command "get-processmitigation | convertto-json"')
    system_process_mitigation = Facter::Core::Execution.execute('powershell.exe -noprofile -nologo -noninteractive -command "get-processmitigation -system | convertto-json"')

    process_mitigation = []

    # JSON.parse(app_process_mitigation).each do |app|
    #   process_mitigation << app
    # end

    process_mitigation << JSON.parse(system_process_mitigation)

    process_mitigation
  end

  def windows_features
    cmd = 'powershell.exe -noprofile -nologo -noninteractive -command "Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State | convertto-json"'
    features = Facter::Core::Execution.execute(cmd)

    ret = {}

    JSON.parse(features).each do |feature|
      ret[feature['FeatureName']] = feature['State'].positive? ? true : false
    end

    ret
  end

  # # Add event log file paths from registry as facts, to be used when enhancing V-73405, V-73407, V-73409
  # def system_event_log_file_path
  #   system_reg_path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'
  #   ps_command = "powershell.exe -noprofile -nologo -noninteractive -command '(get-itemproperty -Path #{system_reg_path} -Name File).file'"
  #   Facter::Core::Execution.execute(ps_command)
  # end

  # def security_event_log_file_path
  #   security_reg_path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'
  #   ps_command = "powershell.exe -noprofile -nologo -noninteractive -command '(get-itemproperty -Path #{security_reg_path} -Name File).file'"
  #   Facter::Core::Execution.execute(ps_command)
  # end

  # def application_event_log_file_path
  #   application_reg_path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application'
  #   ps_command = "powershell.exe -noprofile -nologo -noninteractive -command '(get-itemproperty -Path #{application_reg_path} -Name File).file'"
  #   Facter::Core::Execution.execute(ps_command)
  # end

  ## Add NDTS database and log file names as facts, to be used when enhancing V-73369/V-93029
  # def ntds_database_path
  #   ntds_db_reg_path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
  #   ntds_db_property_name = 'DSA Database File'
  #   ps_command = "powershell.exe -noprofile -nologo -noninteractive -command \"(get-itemproperty -Path #{ntds_db_reg_path} -Name \'#{ntds_db_property_name}\').\'#{ntds_db_property_name}\'\""
  #   Facter::Core::Execution.execute(ps_command)
  # end

  # def ntds_log_path
  #   ntds_log_reg_path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
  #   ntds_log_property_name = 'Database log files path'
  #   ps_command = "powershell.exe -noprofile -nologo -noninteractive -command \"(get-itemproperty -Path #{ntds_log_reg_path} -Name \'#{ntds_log_property_name}\').\'#{ntds_log_property_name}\'\""
  #   Facter::Core::Execution.execute(ps_command)
  # end

  # def ntds_log_files(log_path)
  #   ps_command = "powershell.exe -noprofile -nologo -noninteractive -command \"(Get-ChildItem -Path #{log_path}).FullName | ConvertTo-Json\""
  #   results = Facter::Core::Execution.execute(ps_command)
  #   JSON.parse(results)
  # end

  setcode do
    fact_value = nil

    sys_info = fetch_sys_info

    if sys_info
      fact_value = { 'system' => sys_info }
    end

    domain_info = fetch_domain_info(sys_info)

    if domain_info
      fact_value ||= {}
      fact_value['active_directory'] = domain_info
    end

    #    if Facter.value(:os).dig('release','major') == '2019'
    if Facter.value(:os)['release']['major'] == '2019'
      exploit_protection_data = fetch_exploit_protection_info

      if exploit_protection_data
        fact_value['process_mitigation'] = exploit_protection_data
      end
    end

    fact_value['features'] = windows_features

    # # Add event log file paths from registry as facts, to be used when enhancing V-73405, V-73407, V-73409

    # system_log_file_path = system_event_log_file_path

    # if system_log_file_path
    #   fact_value['system_event_log_file_path'] = system_log_file_path
    # end

    # security_log_file_path = security_event_log_file_path

    # if security_log_file_path
    #   fact_value['security_event_log_file_path'] = security_log_file_path
    # end

    # application_log_file_path = application_event_log_file_path

    # if application_log_file_path
    #   fact_value['application_event_log_file_path'] = application_log_file_path
    # end

    # # Add NDTS database and log file names as facts, to be used when enhancing V-73369/V-93029
    # ntds_db_path = ntds_database_path
    # if ntds_db_path
    #   fact_value['ntds_database_path'] = ntds_db_path
    # end

    # ntds_log_dir_path = ntds_log_path
    # if ntds_log_dir_path
    #   fact_value['ntds_log_path'] = ntds_log_dir_path
    # end

    # ntds_log_dir_contents = ntds_log_files(ntds_log_dir_path)
    # if ntds_log_dir_contents
    #   fact_value['ntds_log_files'] = ntds_log_dir_contents
    # end

    fact_value
  end
end
