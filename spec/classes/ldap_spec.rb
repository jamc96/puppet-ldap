require 'spec_helper'

describe 'ldap' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      
      # compilation checking  
      it { is_expected.to compile }
      it { is_expected.to compile.with_all_deps }
      # class relationship
      it { is_expected.to contain_class('ldap::install') }
      it { is_expected.to contain_class('ldap::config') }
      it { is_expected.to contain_class('ldap::service') }
      # validate resources
      ['openldap-clients','nss-pam-ldapd','pam_ldap','compat-openldap'].each do |package|
        it { is_expected.to contain_package(package).with(ensure: 'present', provider: 'yum')}
      end
      it {
          is_expected.to contain_exec('authconfig_ldap').with(
            command: 'authconfig --enableshadow --enablemd5 --enableldap --enableldapauth --ldapserver="ldap.domain.com" --ldapbasedn="dc=domain,dc=tld" --disableldaptls --enablemkhomedir --updateall',
            path: '/usr/bin:/usr/sbin:/bin:/usr/local/bin',
            refreshonly: true,
          )
      }
      it { is_expected.to contain_service('nslcd').with(ensure: 'running')}
    end
  end
end
