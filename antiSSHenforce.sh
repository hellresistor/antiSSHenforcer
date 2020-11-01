#!/bin/bash
## By: hellresistor 2k9-2k20
## V20.11.1
## This its a Script to Execute on a Ubuntu Server 18.04 LTS VPS on first Booting (Server installing)
## Will Create a sudo user and add Key to SSH access with KEY! Generated on PuttyGen or ssh-keygen
#################################################################################################################
#################################################################################################################
UsrAdm="ADMINUSER"      ## A Admin User 
AutKey="sha2-512 <yourKey> <yourDescriptore>"   ## Paste Your Public Key generated before (puttygen or ssh-keygen)
# Example:
# AutKey="ed25519 AKfifFJSyhds9dCcj9s87tksohjg389176518563b29ohjxs87125gse2k656S113555422b7 myserver"
ListenIP="0.0.0.0" # Default = 0.0.0.0 = all ips can access to SSHPORT
SshGrp="sudo"
SSHPORT="22"
currentscript="$0"
##################################################################################################################

apt install -y lsb-release
if [ -f /etc/os-release ] ; then
source /etc/os-release
else
exit 1
fi
if [ "${ID,,}" = "debian" ] ; then
export DEBIAN_FRONTEND=noninteractive
mv /etc/apt/sources.list /etc/apt/sources.list."$(date +"%Y%m%d%H%M%S")"
echo "## $(date) ##
deb http://deb.debian.org/debian ${VERSION_CODENAME,,} main contrib non-free
deb http://deb.debian.org/debian ${VERSION_CODENAME,,}-backports main contrib non-free
deb http://deb.debian.org/debian ${VERSION_CODENAME,,}-updates main contrib non-free
deb http://security.debian.org/debian-security ${VERSION_CODENAME,,}/updates main contrib non-free" > /etc/apt/sources.list
elif [ "${ID,,}" = "ubuntu" ] ; then
mv /etc/apt/sources.list /etc/apt/sources.list."$(date +"%Y%m%d%H%M%S")"
echo "## $(date) ##
deb http://archive.ubuntu.com/ubuntu ${VERSION_CODENAME,,} main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu ${VERSION_CODENAME,,}-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu ${VERSION_CODENAME,,}-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu ${VERSION_CODENAME,,}-backports main restricted universe multiverse" > /etc/apt/sources.list
else
exit 1 
fi
apt-get update
apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y upgrade
apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y install openssh-server iptables iptables-persistent
# Creating and Generating a Random Password
USERPASS="$(< /dev/urandom tr -cd "[:alnum:]" | head -c 15)" || exit 1
echo -e "${USERPASS}\\n${USERPASS}" | adduser --home /home/"$UsrAdm" --gecos GECOS --shell /bin/bash "$UsrAdm"
usermod -aG sudo "$UsrAdm"
echo "$UsrAdm:$USERPASS" > /home/"$UsrAdm"/userinfo.txt
chmod 500 /home/"$UsrAdm"/userinfo.txt
chown "$UsrAdm" /home/"$UsrAdm"/userinfo.txt
echo -e "$UsrAdm\tALL=NOPASSWD:ALL" >> /etc/sudoers
# Adding Keys to this user and authorized keys file
SSH_DIR=/home/"$UsrAdm"/.ssh
mkdir "$SSH_DIR"
echo "$AutKey" >> "$SSH_DIR"/authorized_keys
chown -R "$UsrAdm" "$SSH_DIR"
chgrp -R "$UsrAdm" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 400 "$SSH_DIR"/authorized_keys
chattr +i "$SSH_DIR"/authorized_keys
echo "CONFIGURE SSH"
groupadd "$SshGrp"
usermod -aG "$SshGrp" "$UsrAdm"
cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config."$(date +"%Y%m%d%H%M%S")"
sed -i -r -e '/^#|^$/ d' /etc/ssh/sshd_config
cat > /etc/ssh/sshd_config <<-EOF
Protocol 2
Port $SSHPORT
ListenAddress $ListenIP
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
AllowGroups $SshGrp
AllowUsers $UsrAdm
SyslogFacility AUTH
LogLevel INFO
PermitRootLogin no
PermitEmptyPasswords no
ClientAliveCountMax 0
ClientAliveInterval 300
LoginGraceTime 30
Compression delayed
StrictModes yes
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile    %h/.ssh/authorized_keys
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
IgnoreRhosts yes
HostbasedAuthentication no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM no
X11Forwarding no
PrintMotd no
TCPKeepAlive no
AcceptEnv LANGUAGE
PermitUserEnvironment no
# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
# Subsystem sftp internal-sftp -f AUTHPRIV -l INFO
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
UseDNS no
Compression no
AllowAgentForwarding no
MaxAuthTries 2
MaxSessions 2
MaxStartups 2
DebianBanner no
ChallengeResponseAuthentication no
EOF
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
cp --preserve /etc/ssh/moduli /etc/ssh/moduli."$(date +"%Y%m%d%H%M%S")"
awk '$5 >= 3072' /etc/ssh/moduli | tee /etc/ssh/moduli.tmp
mv /etc/ssh/moduli.tmp /etc/ssh/moduli
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
iptables --flush
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT 
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -p tcp --dport "$SSHPORT" -m state --state NEW -m recent --update --seconds 60 --hitcount 6 -j DROP
iptables -A INPUT -p tcp --dport "$SSHPORT" -m state --state NEW -m recent --set
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP
iptables-save > /etc/iptables/ip4.rules
service ssh restart
service iptables restart

function finish {
echo "Securely shredding ${currentscript}"; shred -u "${currentscript}"; reboot;
}

trap finish EXIT
