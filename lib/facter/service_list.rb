# frozen_string_literal: true

require 'json'

Facter.add('service_list') do
  confine 'os.family' => 'windows'
  setcode do
    command = 'powershell "Get-Service | Select-Object name | ConvertTo-Json"'
    value = Facter::Core::Execution.execute(command)
    return [] unless value

    JSON.parse(value).map { |v| v.values }.flatten
  end
end
