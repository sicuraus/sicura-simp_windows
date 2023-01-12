# @summary Tests all enabled accounts, local and domain, for PasswordNeverExpires=>true
#
# Tests the PasswordNeverExpires flag on all accounts
#   and posts a NOTIFY if it is set to 'true' for 
#   any accounts not in the exclusion list.
#
# @param exclusions
#   Array of account names to exclude from testing.
# @example
#   simp_windows::password_expiry_exclusions => ['serviceaccount1', 'serviceaccount2']
#
#   simp_windows::password_expiry { 
#     'Passwords must be configured to expire':
#       'enable' => true
#   }
#
class simp_windows::password_expiry (
  Array $exclusions = [],
) {
  $non_expiring_accounts = $facts['non_expiring_accounts']
  unless $non_expiring_accounts == [] {
    if $exclusions == [] {
      $acct_list = $non_expiring_accounts
    } else {
      $acct_list = $non_expiring_accounts.reduce([]) |$memo, $value| {
        if $value in $exclusions {
          $memo
        } else {
          $memo << $value
        }
      }
    }
    unless $acct_list == [] {
      notify { "The following accounts have the 'Password never expires' flag set. ${acct_list}": }
    }
  }
}
