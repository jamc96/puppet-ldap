# #!/bin/ksh
# # Version 1.24
# # 09/12/13: Added commands to register system on Spacewalk
# #           update system with latest patches.
# # 09/14/13: Added command to abort script with fails to install
# #           SpaceWalk client.
# # 09/15/13: Fixed command to obtain IP address from host.
# # 09/24/13: Changed the script to work on Toronto and Vancouver
# #           networks.
# # 10/28/13: Changed script to register any server with Toronto Spacewalk
# # 11/05/13: Changed script to download EPEL packages from Fedora's server
# # 11/26/13: Changed script to make it work for both RHEL and CentOS.
# # 12/12/13: Added installation of Puppet client.
# # 12/26/13: Added moving original CentOS repos to /etc/yum.repos.d.ori,
# #           this will avoid updates being downloaded from CentOS repos
# #           instead of Spacewalk server.
# # 01/07/14: Added NMON installation.
# # 03/17/14: Added step to download CERT for LDAP servers and use different LDAP servers
# #           based on location.
# # 03/19/14: Added command to fix issue with mcelog error messages showing every one hour,
# #           ref: https://clustered.net/knowledgebase.php?action=displayarticle&id=1201
# # 03/20/14: Changed script to subscribe to the channels correspodent to the release of
# #           CentOS that was installed.
# #           Added appmon group to Allowgroup list on sshd_config
# # 04/14/14: Added options to ldap configuration files to detect failover of clients.
# # 04/17/14: Added options to resolv.conf to load balance DNS queries and to only
# #           try each server listed only once.
# # 04/30/14: Added download of sudoers file from Spacewalk server
# # 05/01/14: Added commands to install splunk forwarder.
# # 05/13/14: Added commands to install Xentools on virtual machines.
# # 06/06/14: Fixed the name of the portmap service from Linux to rpcbind.
# # 07/23/14: Removed download of sudoers file from Spacewalk server,
# #           it will be deployed by Puppet.
# # 08/06/14: Changed Puppet Master to be torpforeman1.sandals.com.
# # 08/07/14: Spacewalk subscriptios to EL and SCP channels added.
# # 08/07/14: Spacewalk subscriptios to EL and SCP channels added.
# # 11/03/14: Modified to match new configuration of CentOS channels, instead of version
# #           6.X there will be a 6 channels poiting to the latest updates.
# #           Modified to remove lines setting DNS servers, default gateway or hostname.
# #           from ifcfg files.
# # 01/16/15: Added configurartion of POSTFIX to use relay hosts.
# # 04/24/15: Disabled startup of Sendmail.
# # 10/24/16: Changed script to clear the content of file /etc/logrotate.d/syslog before adding new lines.
#
# # Determine location of the server.
# LOC=`hostname | cut -c 1-3`
#
# # Changes root initial password.
# passwd
#
# # Add DNS resolver options.
# if [[ ! -f /etc/resolv.conf.ori ]]
# then
#  cp -p /etc/resolv.conf /etc/resolv.conf.ori
#  echo "domain  sandals.com" >> /etc/resolv.conf
#  echo "options rotate" >> /etc/resolv.conf
#  echo "options attempts:1" >> /etc/resolv.conf
# fi

# Configure CentOS servers as SpaceWalk client and add subscribe to required channels.
if [[ -f /etc/centos-release ]]
then
 wget http://torpspwalk1/sandals-repos/epel -O /etc/yum.repos.d/epel
 ping -c 5 spacewalk.redhat.com
 rpm -Uhv http://spacewalk.redhat.com/yum/2.0-client/RHEL/6/x86_64/spacewalk-client-repo-2.0-3.el6.noarch.rpm
 ping -c 5 dl.fedoraproject.org
 yum install -y http://dl.fedoraproject.org/pub/epel/6/x86_64/python-hwdata-1.7.3-1.el6.noarch.rpm
 ping -c 5 yum.spacewalkproject.org
 yum install -y rhn-setup yum-rhn-plugin python-dmidecode
 RC=$?
 if [[ $RC != "0" ]]
 then
  echo -e "\n\n\n\n\n"
  echo "*********************************************"
  echo "*********************************************"
  echo "ABORTED : Failed to install Spacewalk client."
  echo "*********************************************"
  echo "*********************************************"
  echo -e "\n\n\n\n\n"
  exit 1
 fi
 rhnreg_ks --serverUrl=http://torpspwalk1/XMLRPC --activationkey=1-1fedea4888b5b4b189420e1452553539
 rpm --import http://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-6
 spacewalk-channel --add -c centos6-base-x86_64 -c centos6-updates-x86_64 -c centos6-scl-x86_64 --user root --password QIzkB36MBg2H
 rm  -f /etc/yum.repos.d/epel
 rm -f /etc/yum.repos.d/CentOS*
 RC=$?
 if [[ $RC != "0" ]]
 then
  echo -e "\n\n\n\n\n"
  echo "***************************************************"
  echo "***************************************************"
  echo "ABORTED : Failed to disable original CentOS repos."
  echo "***************************************************"
  echo "***************************************************"
  echo -e "\n\n\n\n\n"
  exit 1
 fi
fi

# # Install Puppet client on server
# yum install http://yum.puppetlabs.com/puppetlabs-release-el-6.noarch.rpm -y
# yum install puppet --nogpgcheck -y
# if [[ ! -f /etc/puppet/puppet.conf.ori ]]
# then
#  cp -p /etc/puppet/puppet.conf /etc/puppet/puppet.conf.ori
#  echo "# Master Server" >> /etc/puppet/puppet.conf
#  echo "server = torpforeman1.sandals.com" >> /etc/puppet/puppet.conf
# fi

# Install NMON on server and add crontab entry.
if [[ -f /etc/centos-release ]]
then
 wget http://torpspwalk1.sandals.com/packages/nmon/nmon_x86_64_centos6 -O /usr/local/bin/nmon
else
 wget http://torpspwalk1.sandals.com/packages/nmon/nmon_x86_64_rhel6 -O /usr/local/bin/nmon
fi
chmod 555 /usr/local/bin/nmon
echo "00 00 * * * /usr/local/bin/nmon -f -T -N -m /var/log -c 1440 -s 60" >> /var/spool/cron/root

# Update the system with the latest patches.
yum update -y
RC=$?
if [[ $RC != "0" ]]
then
 echo -e "\n\n\n\n\n"
 echo "****************************************************"
 echo "****************************************************"
 echo "ABORTED : Failed to run yum update from post script."
 echo "****************************************************"
 echo "****************************************************"
 echo -e "\n\n\n\n\n"
 exit 1
fi

# Locks all the system account (root excluded).
for ACCT in `awk -F: '{print $1}' /etc/passwd | grep -v "root"`
do
 usermod -s /sbin/nologin $ACCT
 passwd -l $ACCT
done

# Disables cron and at for all users, they need to be
# added explicitly on at.allow and cron.allow.
if [[ -f /etc/cron.deny ]]
 then
  mv /etc/cron.deny /etc/cron.deny.ori
  echo "root" > /etc/cron.allow
 if [[ -f /etc/at.deny ]]
 then
  mv /etc/at.deny /etc/at.deny.ori
  echo "root" > /etc/at.allow
 fi
fi

# Fix for error msg being displayed every one hour for mce
if [[ ! -f /root/mcelog.cron.ori ]]
then
 cp -p /etc/cron.hourly/mcelog.cron /root/mcelog.cron.ori
 sed 's/filter/filter --no-dmi/' /root/mcelog.cron.ori > /etc/cron.hourly/mcelog.cron
fi

# Sets root's e-mail to go to sysadmin@sandals.com .
if [[ ! -f /etc/aliases.ori ]]
then
 cp -p /etc/aliases /etc/aliases.ori
 echo "### Sandals' customization" >> /etc/aliases
 echo "root:sysadmin@sandals.com" >> /etc/aliases
fi

# Adds the hostname to /etc/hosts.
if [[ ! -f /etc/hosts.ori ]]
then
 cp -p /etc/hosts /etc/hosts.ori
 HOST=`hostname`
 IP=`ifconfig  | egrep "172.16|172.20" | awk -F: '{print $2}' | awk '{print $1}'`
 echo "$IP $HOST $HOST.sandals.com" >> /etc/hosts
fi

# Removes lines setting DNS servers, default gateway or hostname from ifcfg files.
NIC=`netstat -rn | grep ^0.0.0.0 | awk '{print $NF}'`
if [[ ! -f /root/ifcfg-${NIC}.ori ]]
then
 grep -q ^NETWORKING /etc/sysconfig/network
 RC=$?
 if [[ $RC != "0" ]]
 then
  echo "NETWORKING=yes" >> etc/sysconfig/network
 fi
 grep -q ^GATEWAY /etc/sysconfig/network
 RC=$?
 if [[ $RC != "0" ]]
 then
  grep ^GATEWAY /etc/sysconfig/network-scripts/ifcfg-${NIC} >> /etc/sysconfig/network
 fi
 cp -p /etc/sysconfig/network-scripts/ifcfg-${NIC} /root/ifcfg-${NIC}.ori
 sed '/^DNS\|^GATEWAY\|^HOSTNAME/d' /root/ifcfg-${NIC}.ori > /etc/sysconfig/network-scripts/ifcfg-${NIC}
fi

# Restricts access to root's HOME.
chmod 750 ~root

# Sets secure path on root's .profile.
if [[ ! -f ~root/.profile.ori ]]
then
 if [[ -f ~root/.profile ]]
 then
  mv ~root/.profile ~root/.profile.ori
 fi
 echo "PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/local/bin:/usr/local/scripts" > ~root/.profile
 echo "export PATH" >> ~root/.profile
fi

# Disables bash profile to avoid settings that will override the ones on
# /etc/profile and /etc/profile.local.
if [[ ! -f /etc/bashrc.ori ]]
then
 mv /etc/bashrc /etc/bashrc.ori
fi

# Adds Sandals' customization to /etc/profile.
if [[ ! -f /etc/profile.ori ]]
then
 cp -p /etc/profile /etc/profile.ori
 echo "### Sandals' customization" >> /etc/profile
 echo "USRID=\`id -u\`" >> /etc/profile
 echo "TMOUT=7200" >> /etc/profile
 echo "readonly TMOUT" >> /etc/profile
 echo "EDITOR=/bin/vi" >> /etc/profile
 echo "VISUAL=\$EDITOR" >> /etc/profile
 echo "if test \"\$USRID\" = 0" >> /etc/profile
 echo "then" >> /etc/profile
 echo " PS1=\"\${HOSTNAME}:\"'\${PWD}'\" # \"" >> /etc/profile
 echo " LS_OPTIONS=\"-a -N \$LS_OPTIONS -T 0\"" >> /etc/profile
 echo "else" >> /etc/profile
 echo " PS1=\"\${USER}@\${HOSTNAME}:\"'\${PWD}'\"> \"" >> /etc/profile
 echo "fi" >> /etc/profile
 echo "export TMOUT EDITOR VISUAL PS1" >> /etc/profile
fi

# Adds  warning message for unauthorized use to the /etc/issue and
# /etc/issue.net files.
if [[ ! -f /etc/issue.ori ]]
then
 mv /etc/issue /etc/issue.ori
 mv /etc/issue.net /etc/issue.net.ori
 echo "WARNING: To protect the system from unauthorized use and" \
 "to ensure that" > /etc/issue
 echo "the system is functioning properly, activities on this system are" \
 >> /etc/issue
 echo "monitored, recorded and subject to audit. Use of this system is" \
 >> /etc/issue
 echo "expressed consent to such monitoring and recording." \
 >> /etc/issue
 echo "Any unauthorized access or use of this Automated Information System" \
 >> /etc/issue
 echo "is prohibited and could be subject to criminal and civil penalties." \
 >> /etc/issue
 ln -s /etc/issue /etc/issue.net
fi

# Disables startup of uneccessary services, will disable everything except
# the services after the "egrep -v" command.
for SERVICE in `chkconfig --list | grep on | awk '{print $1}' | egrep -v \
"auditd|crond|netfs|network|rpcbind|rhnsd|rsyslog|sshd|systat"`
do
 echo "Service ${SERVICE} was disabled" >> /var/log/chkconfig_off.log
 chkconfig ${SERVICE} off
done

# Enable NTP during system startup.
chkconfig ntpd on

# Enable LDAP client authentication.
chkconfig nslcd on

# Enable Puppet client.
chkconfig puppet on

# Enable LDAP with TLS for authentication and configure POSTFIX
wget http://torpspwalk1.sandals.com:/sandals-config/vanpldap1.pem -P /etc/openldap/cacerts
authconfig  --savebackup /root/authconfig.ori
case $LOC in
 tor)
  authconfig  --enableshadow --enablemd5 --enableldap --enableldapauth --ldapserver="torpldap1.sandals.com,torpldap2.sandals.com" --ldapbasedn="dc=sandals,dc=com" --enableldaptls --enablemkhomedir --kickstart ;;
 van)
  authconfig  --enableshadow --enablemd5 --enableldap --enableldapauth --ldapserver="vanpldap1.sandals.com,vanpldap2.sandals.com" --ldapbasedn="dc=sandals,dc=com" --enableldaptls --enablemkhomedir --kickstart ;;
 *)
  echo -e "\n\n\n\n\n"
  echo "*******************************************"
  echo "*******************************************"
  echo "ABORTED : Failed to configure LDAP  client."
  echo "*******************************************"
  echo "*******************************************"
  echo -e "\n\n\n\n\n"
  exit 1;;
esac
echo "### Sandals' customization" >> /etc/nslcd.conf
echo "timelimit 10" >> /etc/nslcd.conf
echo "bind_timelimit 5" >> /etc/nslcd.conf
echo "idle_timelimit 60" >> /etc/nslcd.conf
echo "### Sandals' customization" >> /etc/pam_ldap.conf
echo "timelimit 10" >> /etc/pam_ldap.conf
echo "bind_timelimit 5" >> /etc/pam_ldap.conf
echo "bind_policy soft" >> /etc/pam_ldap.conf
echo "idle_timelimit 60" >> /etc/pam_ldap.conf
echo "nss_reconnect_tries 2" >> /etc/pam_ldap.conf
echo "nss_reconnect_sleeptime 1" >> /etc/pam_ldap.conf
echo "nss_reconnect_maxsleeptime 1" >> /etc/pam_ldap.conf
echo "nss_reconnect_maxconntries 1" >> /etc/pam_ldap.conf

# Configure Postfix to use relay servers
case $LOC in
 tor)
  postconf -e 'relayhost = torsmtp.sandals.com:587' ;;
 van)
  postconf -e 'relayhost = vansmtp.sandals.com:587 ';;
esac
postconf -e 'smtp_use_tls = yes'
chkconfig postfix on

# Disables any services from xinetd.
mv /etc/xinetd.d /etc/xinetd.d.ori
mkdir /etc/xinetd.d

# Disables SSH access to users outside special
# groups, disable root login and set login
# banner.
if [[ ! -f /etc/ssh/sshd_config.ori ]]
then
 cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.ori
 echo "### Sandals' customization" >> /etc/ssh/sshd_config
 echo "PermitRootLogin no" >> /etc/ssh/sshd_config
 echo "AllowGroups sysadmin appmon" >> /etc/ssh/sshd_config
 echo "Banner /etc/issue" >> /etc/ssh/sshd_config
fi

# Disables the use of control-alt-delete to restart  the server.

if [[ ! -f /etc/init/control-alt-delete.conf.ori ]]
then
 mv /etc/init/control-alt-delete.conf /etc/init/control-alt-delete.conf.ori
 sed 's/^start/#start/ ; s/^exec/#exec/'  /etc/init/control-alt-delete.conf.ori > /etc/init/control-alt-delete.conf
fi

# Enables audits on syslog.
if [[ ! -f /etc/rsyslog.conf.ori ]]
then
 cp -p /etc/rsyslog.conf /etc/rsyslog.conf.ori
 echo "### Sandals' customization" >> /etc/rsyslog.conf
 echo "auth,user.*     /var/log/messages" >> /etc/rsyslog.conf
 echo "daemon.*      /var/log/daemon" >> /etc/rsyslog.conf
 echo "syslog.*         /var/log/syslog" >> /etc/rsyslog.conf
 echo "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.*     /var/log/messages" >> /etc/rsyslog.conf
 echo "kern.*              /var/log/kern" >> /etc/rsyslog.conf
 touch /var/log/daemon /var/log/syslog /var/log/kern
 chmod 700 /var/log/daemon /var/log/syslog /var/log/kern
fi

# Configure log rotation.
if [[ ! -f /etc/logrotate.d/syslog.ori ]]
then
 cp -p /etc/logrotate.d/syslog /root/syslog.ori
 echo "/var/log/cron" > /etc/logrotate.d/syslog
 echo "/var/log/daemon" >> /etc/logrotate.d/syslog
 echo "/var/log/kern" >> /etc/logrotate.d/syslog
 echo "/var/log/maillog" >> /etc/logrotate.d/syslog
 echo "/var/log/messages" >> /etc/logrotate.d/syslog
 echo "/var/log/secure" >> /etc/logrotate.d/syslog
 echo "/var/log/spooler" >> /etc/logrotate.d/syslog
 echo "/var/log/syslog" >> /etc/logrotate.d/syslog
 echo "{" >> /etc/logrotate.d/syslog
 echo " rotate 12" >> /etc/logrotate.d/syslog
 echo " weekly" >> /etc/logrotate.d/syslog
 echo " compress" >> /etc/logrotate.d/syslog
 echo " sharedscripts" >> /etc/logrotate.d/syslog
 echo " postrotate" >> /etc/logrotate.d/syslog
 echo "  /bin/kill -HUP \`cat /var/run/syslogd.pid 2> /dev/null\` 2> /dev/null || true" >> /etc/logrotate.d/syslog
 echo " endscript" >> /etc/logrotate.d/syslog
 echo "}" >> /etc/logrotate.d/syslog
fi

# Enables and configures audit service.
if [[ ! -f /etc/audisp/plugins.d/syslog.conf.ori ]]
then
 mv /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.ori
 sed  's/active = no/active = yes/' /etc/audisp/plugins.d/syslog.conf.ori > /etc/audisp/plugins.d/syslog.conf
fi
if [[ ! -f /etc/audit/audit.rules.ori ]]
then
 cp -p /etc/audit/audit.rules /etc/audit/audit.rules.ori
 echo "### Sandals' customization" >> /etc/audit/audit.rules
 echo "### Audit changes on localtime" >> /etc/audit/audit.rules
 echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
 echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
 echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
 echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
 echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
 echo "### Audit changes on SELINUX configuration" >> /etc/audit/audit.rules
 echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
 echo "### Audit changes on sudoers file " >> /etc/audit/audit.rules
 echo "-w /etc/sudoers -p wa -k scope " >> /etc/audit/audit.rules
 echo "### Audit changes on sudo log " >> /etc/audit/audit.rules
 echo "-w /var/log/sudo.log -p wa -k actions " >> /etc/audit/audit.rules
 echo "### Configure auditing mode unchangeable" >> /etc/audit/audit.rules
 echo "--e 2" >> /etc/audit/audit.rules
fi
chkconfig auditd on

# Hardening of IP parameters on /etc/sysctl.conf.
if [[ ! -f /etc/sysctl.conf.ori ]]
then
 cp -p /etc/sysctl.conf /etc/sysctl.conf.ori
 echo "### Sandals' customization" >> /etc/sysctl.conf
 echo "# Configures the server against SYN floods." >> /etc/sysctl.conf
 echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
 echo "# Configures the server to ignore all requests and ICMP broadcast." >> /etc/sysctl.conf
 echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
 echo "# Configures  the server to validate the source of a received packet is valid." >> /etc/sysctl.conf
 echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
 echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
 echo "# Configures the server to disable the forwarding of packets between interfaces." >> /etc/sysctl.conf
 echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf
 echo "# Configures the server to not accept packets with source-route." >> /etc/sysctl.conf
 echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.conf
 echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.conf
 echo "# Configures the server to record logs of suspicious packages." >> /etc/sysctl.conf
 echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.conf
 echo "# Configures the server to not accept packets with redirect." >> /etc/sysctl.conf
 echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
 echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf
fi

# Install Splunk Forwarder
groupadd -g 1300 splunk
useradd -u 1301 -g splunk -c "Splunk monitor user" splunk
echo "splunk" | passwd --stdin splunk
usermod -L splunk && chage -d 0 splunk && usermod -U splunk
mkdir -p /tmp/splunk
rpm -hvi http://torpspwalk1/packages/splunk/splunkforwarder-latest.rpm
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
/opt/splunkforwarder/bin/splunk enable boot-start
cd /opt/splunkforwarder/etc/apps
wget http://torpspwalk1/packages/splunk/osconf.tgz -P /tmp/splunk
tar -zxvf /tmp/splunk/osconf.tgz
cd /opt/splunk/etc/deployment-apps
wget http://torpspwalk1/packages/splunk/splunkdeploy.tgz -P /tmp/splunkdeploy
tar -zxvf /tmp/splunkdeploy/splunkdeploy.tgz
chown -R splunk:splunk /opt/splunkforwarder/etc/apps/search/local
service splunk restart

# Install XEN tools on VMs.
NIC=`netstat -rn | grep ^0.0.0.0 | awk '{print $NF}'`
DRIVER=`ethtool -i $NIC | grep ^driver | awk '{print $2}'`
if [[ $DRIVER = "vif" ]]
then
 rpm -hvi http://torpspwalk1.sandals.com/packages/xentools/xe-guest-utilities-latest.x86_64.rpm  http://torpspwalk1.sandals.com/packages/xentools/xe-guest-utilities-xenstore-latest.x86_64.rpm
fi

# Notify to reboot server
echo -e "\n\n\n\n\n"
echo "*********************************************"
echo "*********************************************"
echo "Completed, please make sure to reboot server"
echo "for all changes to take effect."
echo "*********************************************"
echo "*********************************************"
echo -e "\n\n\n\n\n"
