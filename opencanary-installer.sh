#!/bin/bash
# Originally created by simonxciv. Heavily modified and adapted by Sam Hawkins (https://github.com/hawksj/)
# https://github.com/hawksj/customisable-opencanary-installer

# Check if script is being run as root by EUID
if [[ $EUID -ne 0 ]]
then
    echo "This script must be run as root (sudo). Please execute the script again with root privileges. Aborting..."
    exit 1
fi

# Tests internet connection by trying to access Google 3 times with 20 second timeout. 
echo "Testing internet connection, please wait..."
wget -q -t 3 -T 20 --spider http://google.com

if [ $? -eq 0 ]
then
    echo "Internet connection established. Continuing with installation..."
else
    echo "Unable to reach internet."
    read -p 'Enter the static IP/Mask in CIDR notation for the eth0 interface (e.g. 127.0.0.1/16). Leave blank to skip: ' cidrip
    while [[ ! "$cidrip" =~ (^([0-9.]+\/[0-9]{1,2})$)|(^$) ]]; do
        echo "Please try again. Use CIDR notation or skip."
        read -p 'Enter the static IP/Mask in CIDR notation for the eth0 interface (e.g. 127.0.0.1/16). Leave blank to skip: ' cidrip
    done
    # If no IP address is entered, exit script with code 1.
    if test -z "$cidrip"
    then
        echo "Please ensure firewall authentication or manually set static IP. Edit DHCP config file under /etc/dhcpcd.conf"
        echo "Aborting..."
        exit 1
    # If an IP address was entered, ask for other required network details
    else
        read -p "What is the IP address of your router/gateway? " router
        read -p "What DNS servers should be used? (Space separated): " dnsservers
        # Write IP configuration to dhcpcd config file. 
        # The command must be indented like this to avoid the spaces being entered in the config file
        cat >> /etc/dhcpcd.conf <<- EOL

interface eth0
static ip_address=$cidrip
static routers=$router
static domain_name_servers=$dnsservers
EOL

        echo "/etc/dhcpcd.conf written. Must reboot to apply changes. Please execute the script again following reboot."
        # It is possible to restart the interface and continue the script, but the SSH session will be disconnected and there is no way to view the output of the script if it continues running.
        # Schedule shutdown in 1 minute so the script can safely exit.
        shutdown -r 1
        exit 0
    fi
fi

# Get the device name to use for the canary
read -p 'What hostname do you want to use? [A-Z,a-z,0-9,hyphen,underscore]: ' hs

# Check whether the hostname input is empty
if test -z "$hs"
then
      # If the hostname is empty, do nothing. Set the hostname variable to use
      echo "Not changing hostname"
      hs=$(hostname)
else
# Validate the hostname provided matches the required pattern
    while [[ ! "$hs" =~ ^([A-Za-z0-9-]+)$ ]]; do
        read -p "Wrong hostname format. Re-enter using only A-Z, a-z, 0-9, and hyphens: " hs
    done

# Get the IP address for the syslog server
read -p 'What is the IP address for your syslog server? ' syslogip

# Get the port to use for the syslog server
read -p 'What port is your syslog server listening on? ' syslogport

# Asks users to install Samba
read -p 'Would you like to install the Samba module to enable SMB emulation? [Y/N]: ' smbinstall

# Asks user which modules to enable
modules=()
echo "You will now be asked about commonly used modules. Type 'true' or 'false' to enable or disable them."
read -p 'Enable Git? ' modules[0]
read -p 'Enable FTP? ' modules[1]
read -p 'Enable HTTP? ' modules[2]
read -p 'Enable Port Scan? (WARNING: Will spam you with hundreds of logs if the device is scanned!) ' modules[3]
read -p 'Enable SSH? (Real SSH must be disabled or moved to alternative port) ' modules[4]
read -p 'Enable SNMP? ' modules[5]
echo "Done. Other modules must be manually enabled in config file."

echo "Thank you for configuration. The script will now install all dependencies and update the OS. This will take a while and the device will reboot automatically at the end."


# Set up unattended-upgrades file
#cat >/etc/apt/apt.conf.d/50unattended-upgrades <<EOL
#Unattended-Upgrade::Allowed-Origins {
#    "\${distro_id}:\${distro_codename}";
#    "\${distro_id}:\${distro_codename}-security";
#    "\${distro_id}ESM:\${distro_codename}";
#    "\${distro_id}:\${distro_codename}-updates";
#}
#Unattended-Upgrade::Remove-Unused-Dependencies "true";
#Unattended-Upgrade::Automatic-Reboot "true";
#Unattended-Upgrade::Automatic-Reboot-Time "02:38";
#EOL

# Enable unattended upgrades
#cat >/etc/apt/apt.conf.d/20auto-upgrades <<EOL
#APT::Periodic::Update-Package-Lists "1";
#APT::Periodic::Download-Upgradeable-Packages "1";
#APT::Periodic::AutocleanInterval "7";
#APT::Periodic::Unattended-Upgrade "1";
#EOL

# Install OpenCanary dependencies
#yes | pip install rdpy
#yes | pip install scapy pcapy

# Update the OS
apt update && apt upgrade -y

# Install dependencies
apt install -y git python3 python3-dev python3-pip python3-scapy python3-setuptools screen lsof
case $smbinstall in
[Yy] | [Yy][Ee][Ss] )
    apt install -y samba
    ;;
*)
    echo "Not installing Samba"
    ;;
esac
apt update && apt upgrade -y

# Install OpenCanary
python3 -m pip install opencanary

# The OpenCanary package in pip doesn't work, but nor does just cloning the repo. Need to do both for a working install and to be safe.
git clone https://github.com/thinkst/opencanary
cd opencanary
python3 setup.py sdist && python3 setup.py install

# This file doesn't get moved automatically. 


# Reset the hostname
echo "$hs" > /etc/hostname
cat >/etc/hosts <<EOL
127.0.0.1   localhost
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.1.1   $hs
EOL
hostnamectl set-hostname "$hs"
fi

# Generate a new config file
cat >opencanary.conf <<EOL
{
    "device.node_id": "$hs",
    "git.enabled": ${modules[0]},
    "git.port" : 9418,
    "ftp.enabled": ${modules[1]},
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
    "http.banner": "Apache/2.2.22 (Ubuntu)",
    "http.enabled": ${modules[2]},
    "http.port": 80,
    "http.skin": "nasLogin",
    "httpproxy.enabled" : false,
    "httpproxy.port": 8080,
    "httpproxy.skin": "squid",
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {
                    "format": "%(message)s"
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout"
                },
                "syslog-unix": {
                    "class": "logging.handlers.SysLogHandler",
                    "address": [
                        "$syslogip",
                        $syslogport
                    ],
                    "socktype": "ext://socket.SOCK_DGRAM"
                },
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/tmp/opencanary.log"
                },
                "SMTP": {
                    "class": "logging.handlers.SMTPHandler",
                    "mailhost": ["mail.domain.com", 25],
                    "fromaddr": "canary@domain.com",
                    "toaddrs" : ["me@domain.com"],
                    "subject" : "OpenCanary Alert from $hs"
                }
            }
        }
    },
    "portscan.enabled": ${modules[3]},
    "portscan.logfile":"/var/log/kern.log",
    "portscan.synrate": 5,
    "portscan.nmaposrate": 5,
    "portscan.lorate": 3,
    "smb.auditfile": "/var/log/samba-audit.log",
    "smb.enabled": false,
    "mysql.enabled": false,
    "mysql.port": 3306,
    "mysql.banner": "5.5.43-0ubuntu0.14.04.1",
    "ssh.enabled": ${modules[4]},
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-4",
    "redis.enabled": false,
    "redis.port": 6379,
    "rdp.enabled": false,
    "rdp.port": 3389,
    "sip.enabled": false,
    "sip.port": 5060,
    "snmp.enabled": ${modules[5]},
    "snmp.port": 161,
    "ntp.enabled": false,
    "ntp.port": 123,
    "tftp.enabled": false,
    "tftp.port": 69,
    "tcpbanner.maxnum":10,
    "tcpbanner.enabled": false,
    "tcpbanner_1.enabled": false,
    "tcpbanner_1.port": 8001,
    "tcpbanner_1.datareceivedbanner": "",
    "tcpbanner_1.initbanner": "",
    "tcpbanner_1.alertstring.enabled": false,
    "tcpbanner_1.alertstring": "",
    "tcpbanner_1.keep_alive.enabled": false,
    "tcpbanner_1.keep_alive_secret": "",
    "tcpbanner_1.keep_alive_probes": 11,
    "tcpbanner_1.keep_alive_interval":300,
    "tcpbanner_1.keep_alive_idle": 300,
    "telnet.enabled": false,
    "telnet.port": 23,
    "telnet.banner": "",
    "telnet.honeycreds": [
        {
            "username": "admin",
            "password": "\$pbkdf2-sha512\$19000\$bG1NaY3xvjdGyBlj7N37Xw\$dGrmBqqWa1okTCpN3QEmeo9j5DuV2u1EuVFD8Di0GxNiM64To5O/Y66f7UASvnQr8.LCzqTm6awC8Kj/aGKvwA"
        },
        {
            "username": "admin",
            "password": "admin1"
        }
    ],
    "mssql.enabled": false,
    "mssql.version": "2012",
    "mssql.port":1433,
    "vnc.enabled": false,
    "vnc.port":5000
}
EOL

# Replace the default created opencanary conf file
mv -f opencanary.conf /root/.opencanary.conf
cp bin/opencanary.tac /usr/local/bin/opencanary.tac

echo "Config file written. To enable SMTP reporting, edit the SMTP Handler options in /root/.opencanary.conf, or delete the SMTP class to disable it."
echo "OpenCanary supports many modules and handlers not listed here. Refer to the official documentation and the config file in /root/.opencanary.conf to view."

# Create a systemd service file
echo "Creating opencanary.service file."
cat >/etc/systemd/system/opencanary.service <<EOL
[Unit]
Description=OpenCanary honeypot service
After=syslog.target
After=network.target

[Service]
User=root
Restart=always
RestartSec=5
Type=simple
ExecStart=screen -DmS opencanary opencanaryd --dev
ExecStop=screen -S opencanary -X stuff ^C

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd services
systemctl daemon-reload

# Enable and start the new systemd service
systemctl enable opencanary.service
systemctl start opencanary.service

# Reboot the canary
echo "Rebooting device."
reboot
