# == Class ldap::install
#
# This class is called from ldap for install.
#
class ldap::install inherits ldap {
  # ensure package installed
  ['openldap-clients','nss-pam-ldapd','pam_ldap','compat-openldap'].each |$package| {
    package { $package:
      ensure   => $ldap::package_ensure,
      provider => 'yum',
    }
  }
}
