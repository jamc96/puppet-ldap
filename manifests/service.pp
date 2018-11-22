# == Class ldap::service
#
# This class is meant to be called from ldap.
# It ensure the service is running.
#
class ldap::service inherits ldap {
  # ensure service running
  service { 'nslcd':
    ensure     => $ldap::service_ensure,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}
