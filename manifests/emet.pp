# @summary Installs Enhanced Mitigation Experience Toolkit
#
# Installs Enhanced Mitigation Experience Toolkit
#
# @param package_name
#   Name of the package as shown in 'puppet resource package'
# @param package_ensure
#   Determines state of the package.  'installed' and 'absent' are valid.
# @param package_source
#   Location of the installation binary.
# @param install_options
#   Additional command line options for the installation binary. See the documentation
#   for the installation binary for details.
# @example
#   include simp_windows::emet
class simp_windows::emet (
  String             $package_name,
  String             $package_ensure,
  Stdlib::Filesource $package_source,
  Array              $install_options,
) {
  package { $package_name:
    ensure          => $package_ensure,
    source          => $package_source,
    install_options => $install_options,
  }
}
