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
  Enum['present','absent'] $package_ensure   = 'present',
  Enum['running','stopped'] $service_ensure  = 'running',
  Boolean $ldapauth                          = true,
  Boolean $ldaptls                           = false,
  Optional[String] $ldapserver               = 'ldap.domain.com',
  Pattern[/^(dc\=\w+\,?){1,2}$/] $ldapbasedn = 'dc=domain,dc=tld',
  Boolean $md5                               = true,
  Boolean $shadow                            = true,
  Boolean $mkhomedir                         = true,
  Boolean $savebackup                        = true,
  Boolean $ldap                              = true,
  Optional[String] $key                      = undef,
  String $cacert_dir                         = '/etc/openldap/cacerts'
){
  # default variables
  $ldapserver_flg = "ldapserver=\"${ldapserver}\""
  $ldapbasedn_flg = "ldapbasedn=\"${ldapbasedn}\""
  $ldap_flg = bool2str($ldap,'enableldap', 'disableldap')
  $ldapauth_flg = bool2str($ldapauth, 'enableldapauth', 'disableldapauth')
  $ldaptls_flg = bool2str($ldaptls, 'enableldaptls', 'disableldaptls')
  $md5_flg = bool2str($md5, 'enablemd5', 'disablemd5')
  $shadow_flg = bool2str($shadow, 'enableshadow', 'disableshadow')
  $mkhomedir_flg = bool2str($mkhomedir, 'enablemkhomedir', 'disablekhomedir')
  $savebackup_flg = bool2str($savebackup, 'savebackup', 'savebackup')
  # enable TLS for authentication
  $key_ensure = $ldaptls ? {
    true => 'present',
    default => 'absent',
  }
  # concat config array
  $config_array = [$shadow_flg, $md5_flg, $ldap_flg, $ldapauth_flg, $ldapserver_flg, $ldapbasedn_flg, $ldaptls_flg, $mkhomedir_flg].join(' --')
  # creating config string
  $authconfig_ldap = "authconfig --${config_array} --updateall"
  # class containment
  contain ldap::install
  contain ldap::config
  contain ldap::service
  # class relationship
  Class['::ldap::install']
  -> Class['::ldap::config']
  ~> Class['::ldap::service']

}
