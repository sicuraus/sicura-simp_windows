# @summary Detect and Notify on unused accounts
#
# Searches the local system, or Active Directory if a Domain Controller,
# for accounts that are enabled and have not been logged into for the
# defined number of days.  Notify thrown if any are found.
#
# @example
#   include simp_windows::unused_accounts
#
# @param exclusions
#   Array containing account names to exclude from alerting.
# @param maxdays
#   Number of days after which an account is considered 'unused'.
#   Defaults to 35. The custom fact gathers all active accounts that
#   have not been logged into for 17 days.
#
class simp_windows::unused_accounts (
  Array $exclusions = [],
  Numeric $maxdays = 35,
) {
  unless $facts['unused_accounts'] == undef {
    $unused_accounts = $facts['unused_accounts']['accounts']
    unless $unused_accounts == [] {
      $acct_list = $unused_accounts.reduce([]) |$memo, $hash| {
        if $hash[0] in $exclusions {
          $memo
        } else {
          if $hash[1] == '' {
            $memo << $hash[0]
          } else {
            $lastlogin = TimeStamp.new(Numeric($hash[1])/1000)
            $maxageseconds = 60 * 60 * 24 * $maxdays
            $oldestdate = TimeStamp.new((Numeric($facts['unused_accounts']['sys_date_int']))/1000 - $maxageseconds)

            if $lastlogin < $oldestdate {
              $memo << $hash[0]
            }
          }
        }
      }
      unless $acct_list == [] {
        notify { "The following accounts should be reviewed for lack of use. ${acct_list}": }
      }
    }
  }
}
