# == Class ldap::config
#
# This class is called from ldap for service config.
#
class ldap::config inherits ldap {
  # Making the configuration with authconfig
  exec { 'authconfig_ldap':
    command     => "$::ldap::authconfig_ldap",
    path        => '/usr/bin:/usr/sbin:/bin:/usr/local/bin',
    refreshonly => $::ldap_connection,
  }
}
