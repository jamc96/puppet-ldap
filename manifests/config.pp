# == Class ldap::config
#
# This class is called from ldap for service config.
#
class ldap::config inherits ldap {
  # enable TLS
  if $ldap::ldaptls {
    unless $ldap::key {
      fail('key parameter is required to enable TLS')
    }else {
        file { $ldap::cacert_dir:
          ensure => directory,
        }
        file { "${ldap::cacert_dir}/server.pem":
          ensure  => $ldap::key_ensure,
          owner   => 'root',
          group   => 'root',
          source  => $ldap::key,
          notify  => Exec['authconfig_ldap'],
          require => File[$ldap::cacert_dir],
      }
    }
  }
  # apply configurations for ldap
  exec { 'authconfig_ldap':
    command     => $::ldap::authconfig_ldap,
    path        => '/usr/bin:/usr/sbin:/bin:/usr/local/bin',
    refreshonly => $::ldap_connection,
  }
}
