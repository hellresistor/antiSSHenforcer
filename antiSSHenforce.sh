#!/bin/bash
## By: hellresistor 2k11-2k19
## V19.8.29.22
## This its a Script to Execute on a Ubuntu Server 18.04 LTS VPS on first Booting (Server installing)
## Will Create a sudo user and add Key to SSH access with KEY! Generated on PuttyGen or ssh-keygen
#################################################################################################################

UsrAdm="ADMINUSER"      ## A Admin User 
AutKey="ed25519 <yourKey> <yourDescriptore>"   ## Paste Your Public Key generated before (puttygen or ssh-keygen)
# Example:
# AutKey="ed25519 AKfifFJSyhds9dCchsSJHFhsaiugsduidSD2389176518563b29ohjxs87125gse2k656S113555422b7 myserver"
SshGrp=remote
SSHPORT=22
COUNTRY="cz"            ## Your prefered package server Country
currentscript="$0"
##################################################################################################################

cat<<EOF>/etc/apt/sources.list
deb http://$COUNTRY.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse
deb http://$COUNTRY.archive.ubuntu.com/ubuntu/ bionic-security main restricted universe multiverse
deb http://$COUNTRY.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse
EOF

apt-get update
apt-get install -y --install-recommends linux-generic-hwe-18.04

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
# Secure Keys
chown -R "$UsrAdm" "$SSH_DIR"
chgrp -R "$UsrAdm" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 400 "$SSH_DIR"/authorized_keys
chattr +i "$SSH_DIR"/authorized_keys
echo "CONFIGURE SSH"
groupadd "$SshGrp"
usermod -aG "$SshGrp" "$UsrAdm"

cp --preserve /etc/ssh/sshd_config /etc/ssh/sshd_config.'$(date +"%Y%m%d%H%M%S")'
sed -i -r -e '/^#|^$/ d' /etc/ssh/sshd_config
cat > /etc/ssh/sshd_config <<-EOF
Protocol 2
Port "$SSHPORT"
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
LogLevel VERBOSE
PermitUserEnvironment no
# Log sftp level file access (read/write/etc.) that would not be easily logged otherwise.
Subsystem sftp internal-sftp -f AUTHPRIV -l INFO
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitEmptyPasswords no
IgnoreRhosts yes
UseDNS no
Compression no
TCPKeepAlive no
AllowAgentForwarding no
PermitRootLogin no
HostbasedAuthentication no
AllowGroups "$SshGrp"
ClientAliveCountMax 0
ClientAliveInterval 600
ListenAddress 0.0.0.0
LoginGraceTime 30
MaxAuthTries 2
MaxSessions 2
MaxStartups 2
PasswordAuthentication no
DebianBanner no
UsePAM no
AuthorizedKeysFile    %h/.ssh/authorized_keys
PubkeyAuthentication yes
ChallengeResponseAuthentication no
EOF

cp --preserve /etc/ssh/moduli /etc/ssh/moduli."$(date +"%Y%m%d%H%M%S")"

# Remove all moduli smaller than 3072 bits.
awk '$5 >= 3072' /etc/ssh/moduli | tee /etc/ssh/moduli.tmp

mv /etc/ssh/moduli.tmp /etc/ssh/moduli

service ssh restart

function finish {
echo "Securely shredding ${currentscript}"; shred -u "${currentscript}"; reboot;
}

trap finish EXIT
