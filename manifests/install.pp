# == Class ldap::install
#
# This class is called from ldap for install.
#
class ldap::install {

  Package {
    ensure => present,
    provider => 'yum',
  }
  package {
    $::ldap::package_name: ;
    $::ldap::dependencies: ;
  }
}
