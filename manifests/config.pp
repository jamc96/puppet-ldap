# == Class ldap::config
#
# This class is called from ldap for service config.
#
class ldap::config {
  # Making the configuration with authconfig
  exec { 'ldap_command_auth':
    command     => $::ldap::ldap_updt_command,
    path        => '/usr/bin:/usr/sbin:/bin:/usr/local/bin',
    refreshonly => $::ldap::ldap_connection_exist_flg,
  }
}
