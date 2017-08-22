# == Class ldap::params
#
# This class is meant to be called from ldap.
# It sets variables according to platform.
#
class ldap::params {
  case $::osfamily {
    'Debian': {
      $package_name  = ['openldap-clients','openldap']
      $dependencies  = ['nss-pam-ldapd','pam_ldap','compat-openldap']
      $service_name  = 'nslcd'
    }
    'RedHat': {
      $package_name  = ['openldap-clients']
      $dependencies  = ['nss-pam-ldapd','pam_ldap','compat-openldap']
      $service_name  = 'nslcd'
    }
    default: {
      fail("${::operatingsystem} not supported")
    }
  }
}
