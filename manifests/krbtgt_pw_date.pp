# @summary Tests password date of krbtgt account in Active Directory
#
# Tests the password last set date of the krbtgt account in Active Directory
#   and posts a NOTIFY if it is older than 180 days.
#
# @param testpwdate
#   Enables the test, defaults to 'false'.
# @param maxagedays
#   Maximum age in days for the 'password last set' date.
# @example
#   simp_windows::krbtgt_pw_date { 
#     'Test last set date':
#       'testpwdate': true
#       'maxagedays': '180'
#   }
define simp_windows::krbtgt_pw_date (
  Boolean $testpwdate = false,
  Integer $maxagedays = 180,
) {
  if $testpwdate {
    unless empty($facts['krbtgt_pw_date']) {
      # get passwordlastset date from facts
      $pwlastsetdate = TimeStamp.new(Numeric($facts['krbtgt_pw_date']['pw_date_int'])/1000)
      # calculate today - 180 days
      $maxageseconds = 60 * 60 * 24 * $maxagedays
      $oldestpwdate = TimeStamp.new((Numeric($facts['krbtgt_pw_date']['sys_date_int']))/1000 - $maxageseconds)
      # compare passwordlastset date with calculated date
      # notify if older
      if $pwlastsetdate < $oldestpwdate {
        notify { 'krbtgt pw date':
        message => "FAILURE: The krbtgt account password is more than ${maxagedays} days old, please change it as soon as possible." }
      }
    }
  }
}
