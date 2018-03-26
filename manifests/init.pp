# Class: ldap
# ===========================
#
# Full description of class ldap here.
#
# Parameters
# ----------
#
# * `sample parameter`
#   Explanation of what this parameter affects and what it defaults to.
#   e.g. "Specify one or more upstream ntp servers as an array."
#
class ldap (
  $package_name          = $::ldap::params::package_name,
  $service_name          = $::ldap::params::service_name,
  $dependencies          = $::ldap::params::dependencies,
  $ldap_connection_exist = undef,
  $ldap                  = true,
  $ldapauth              = true,
  $ldaptls               = false,
  $ldapserver            = undef,
  $ldapbasedn            = undef,
  $md5                   = true,
  $shadow                = true,
  $mkhomedir             = true,
  $savebackup            = true,
  $cacerts               = undef,

) inherits ::ldap::params {

# validate parameters here
case $::osfamily {
  'RedHat' : {
    # Enable LDAP Service
    if $ldap {
      if !$ldapserver {
        fail('The ldapserver parameter is required when ldap set to true')
      }else {
        $ldapserver_flg = "--ldapserver \"${ldapserver}\""
      }
      if !$ldapbasedn {
        fail('The ldapbasedn parameter is required when ldap set to true')
      }else {
        $ldapbasedn_flg = "--ldapbasedn \"${ldapbasedn}\""
      }
      #Converting variable into boolean
      $ldap_connection_exist_flg = str2bool($ldap_connection_exist)

      $ldap_flg = $ldap ? {
        true     => '--enableldap',
        default  => '--disableldap',
      }
      $ldapauth_flg = $ldapauth ? {
        true     => '--enableldapauth',
        default  => '--disableldapauth',
      }
      # Enable LDAP with TLS for authentication
      if $ldaptls {
        if !$cacerts {
          fail('The cacerts parameter is required when ldaptls set to true')
        }
        $ldaptls_flg = $ldaptls ? {
          true     => '--enableldaptls',
          default  => '--disableldaptls',
        }
      }
      $md5_flg = $md5 ? {
        true     => '--enablemd5',
        default  => '--disablemd5',
      }
      $shadow_flg = $shadow ? {
        true     => '--enableshadow',
        default  => '--disableshadow',
      }
      $mkhomedir_flg = $mkhomedir ? {
        true     => '--enablemkhomedir',
        default  => '--disablekhomedir',
      }
      $savebackup_flg = $savebackup ? {
        true     => '--savebackup',
        default  => '--savebackup',
      }

    }
    # Creating variables to connect with ldap
    $ldap_test_command = "authconfig  ${shadow_flg} ${md5_flg} ${ldap_flg} ${ldapauth_flg} ${ldapserver_flg} ${ldapbasedn_flg} ${ldaptls_flg} ${mkhomedir_flg} --test"
    $ldap_updt_command = "authconfig  ${shadow_flg} ${md5_flg} ${ldap_flg} ${ldapauth_flg} ${ldapserver_flg} ${ldapbasedn_flg} ${ldaptls_flg} ${mkhomedir_flg} --updateall"

  } default : {
    fail("$::osfamily is not supported")
  }
}
  # Adding relationship to the class
  contain ldap::install
  contain ldap::config
  contain ldap::service
  contain ldap::params

  Class['::ldap::install']
  -> Class['::ldap::config']
  ~> Class['::ldap::service']

}
