# == Class ldap::service
#
# This class is meant to be called from ldap.
# It ensure the service is running.
#
class ldap::service {

  service { $::ldap::service_name:
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }
}
