# Facter to determine if the ldap connection is working
Facter.add('ldap_connection') do
  confine kernel: 'Linux'
  setcode do
    # set default variables
    user = Facter::Util::Resolution.exec('/usr/bin/env id Admin')
    # validate connection
    if user
      (user.split(' ').any? { |key| key =~ %r{/^uid=(\d+)/} }) ? true : false
    end
  end
end
